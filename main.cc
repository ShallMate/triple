#include <chrono>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "yacl/base/byte_container_view.h"
#include "yacl/base/exception.h"
#include "yacl/crypto/rand/rand.h"
#include "yacl/link/test_util.h"

struct BitVec {
  size_t nbits = 0;
  std::vector<uint64_t> w;

  BitVec() = default;
  explicit BitVec(size_t n) { resize(n); }

  static inline size_t NumWords(size_t nbits) { return (nbits + 63) / 64; }

  inline void resize(size_t n) {
    nbits = n;
    w.assign(NumWords(n), 0);
  }

  inline size_t bytes() const { return w.size() * sizeof(uint64_t); }
  inline uint64_t* data() { return w.data(); }
  inline const uint64_t* data() const { return w.data(); }

  inline void mask_last_word() {
    if (w.empty()) return;
    const size_t r = nbits & 63;
    if (r == 0) return;
    const uint64_t m = (r == 64) ? ~uint64_t(0) : ((uint64_t(1) << r) - 1);
    w.back() &= m;
  }

  inline bool get(size_t i) const { return (w[i >> 6] >> (i & 63)) & 1; }

  static BitVec Rand(size_t n) {
    BitVec out(n);
    auto rb = yacl::crypto::RandBytes(out.bytes());
    std::memcpy(out.w.data(), rb.data(), out.bytes());
    out.mask_last_word();
    return out;
  }

  inline void XorInplace(const BitVec& b) {
    YACL_ENFORCE(nbits == b.nbits, "BitVec xor size mismatch");
    for (size_t i = 0; i < w.size(); ++i) w[i] ^= b.w[i];
  }

  static BitVec And(const BitVec& a, const BitVec& b) {
    YACL_ENFORCE(a.nbits == b.nbits, "BitVec and size mismatch");
    BitVec out(a.nbits);
    for (size_t i = 0; i < out.w.size(); ++i) out.w[i] = a.w[i] & b.w[i];
    return out;
  }

  static BitVec Xor(const BitVec& a, const BitVec& b) {
    YACL_ENFORCE(a.nbits == b.nbits, "BitVec xor size mismatch");
    BitVec out(a.nbits);
    for (size_t i = 0; i < out.w.size(); ++i) out.w[i] = a.w[i] ^ b.w[i];
    return out;
  }

  inline bool Equals(const BitVec& b) const {
    if (nbits != b.nbits) return false;
    for (size_t i = 0; i < w.size(); ++i) {
      if (w[i] != b.w[i]) return false;
    }
    return true;
  }
};

static inline void SendBitVec(const std::shared_ptr<yacl::link::Context>& ctx,
                              int dst, const std::string& tag,
                              const BitVec& v) {
  ctx->SendAsync(dst,
                 yacl::ByteContainerView(
                     reinterpret_cast<const uint8_t*>(v.data()), v.bytes()),
                 tag);
}

static inline BitVec RecvBitVec(const std::shared_ptr<yacl::link::Context>& ctx,
                                int src, const std::string& tag,
                                size_t nbits) {
  BitVec out(nbits);
  auto buf = ctx->Recv(src, tag);

  const int64_t got_i64 = buf.size();
  YACL_ENFORCE(got_i64 >= 0, "RecvBitVec got negative size={}", got_i64);
  const size_t got = static_cast<size_t>(got_i64);
  const size_t expect = out.bytes();
  YACL_ENFORCE(got == expect, "RecvBitVec size mismatch: got={}, expect={}", got, expect);

  std::memcpy(out.data(), buf.data(), out.bytes());
  out.mask_last_word();
  return out;
}

struct RotSendBits { BitVec u0; BitVec u1; };
struct RotRecvBits { BitVec choice; BitVec ub; };
struct EdgeRot { RotSendBits send; RotRecvBits recv; };
struct BitTripleShare { BitVec a; BitVec b; BitVec c; };

static BitTripleShare GenNPartyBitTriplesFromPrecomputedRot(
    const std::shared_ptr<yacl::link::Context>& ctx, size_t nbits,
    const std::vector<std::unique_ptr<RotSendBits>>& rot_send,
    const std::vector<std::unique_ptr<RotRecvBits>>& rot_recv) {
  const int rank = ctx->Rank();
  const int world = ctx->WorldSize();
  YACL_ENFORCE((int)rot_send.size() == world, "rot_send size mismatch");
  YACL_ENFORCE((int)rot_recv.size() == world, "rot_recv size mismatch");

  BitTripleShare out;
  out.a = BitVec::Rand(nbits);
  out.b = BitVec(nbits);
  out.c = BitVec(nbits);

  bool has_incoming = false;
  for (int peer = 0; peer < world; ++peer) {
    if (peer == rank) continue;
    if (!rot_recv[peer]) continue;

    YACL_ENFORCE(rot_recv[peer]->choice.nbits == nbits, "rot_recv.choice size mismatch");
    YACL_ENFORCE(rot_recv[peer]->ub.nbits == nbits, "rot_recv.ub size mismatch");

    if (!has_incoming) {
      out.b = rot_recv[peer]->choice;
      has_incoming = true;
    } else {
      YACL_ENFORCE(out.b.Equals(rot_recv[peer]->choice),
                   "Incoming ROT choices inconsistent, peer={}", peer);
    }
  }

  if (!has_incoming) {
    out.b = BitVec::Rand(nbits);
  }

  out.c.XorInplace(BitVec::And(out.a, out.b));

  for (int peer = 0; peer < world; ++peer) {
    if (peer == rank) continue;
    if (!rot_send[peer]) continue;

    out.c.XorInplace(rot_send[peer]->u0);

    BitVec delta = BitVec::Xor(rot_send[peer]->u0, rot_send[peer]->u1);
    delta.XorInplace(out.a);

    SendBitVec(ctx, peer,
               "np_delta/" + std::to_string(rank) + "->" + std::to_string(peer),
               delta);
  }

  for (int peer = 0; peer < world; ++peer) {
    if (peer == rank) continue;
    if (!rot_recv[peer]) continue;

    BitVec delta = RecvBitVec(ctx, peer,
                              "np_delta/" + std::to_string(peer) + "->" + std::to_string(rank),
                              nbits);

    BitVec bd = BitVec::And(out.b, delta);
    BitVec t  = BitVec::Xor(rot_recv[peer]->ub, bd);
    out.c.XorInplace(t);
  }

  ctx->WaitLinkTaskFinish();
  return out;
}

static bool ValidateTriplesOpenToRank0(const std::shared_ptr<yacl::link::Context>& ctx,
                                       const BitTripleShare& s) {
  const int rank = ctx->Rank();
  const int world = ctx->WorldSize();
  const size_t nbits = s.a.nbits;
  YACL_ENFORCE(s.b.nbits == nbits && s.c.nbits == nbits, "Validate size mismatch");

  if (rank != 0) {
    SendBitVec(ctx, 0, "open/a/" + std::to_string(rank), s.a);
    SendBitVec(ctx, 0, "open/b/" + std::to_string(rank), s.b);
    SendBitVec(ctx, 0, "open/c/" + std::to_string(rank), s.c);

    auto verdict = ctx->Recv(0, "open/verdict");
    YACL_ENFORCE(verdict.size() == 1, "verdict size invalid");
    return verdict.data<uint8_t>()[0] != 0;
  }

  BitVec A = s.a, B = s.b, C = s.c;

  for (int p = 1; p < world; ++p) {
    BitVec ra = RecvBitVec(ctx, p, "open/a/" + std::to_string(p), nbits);
    BitVec rb = RecvBitVec(ctx, p, "open/b/" + std::to_string(p), nbits);
    BitVec rc = RecvBitVec(ctx, p, "open/c/" + std::to_string(p), nbits);
    A.XorInplace(ra);
    B.XorInplace(rb);
    C.XorInplace(rc);
  }

  BitVec expect = BitVec::And(A, B);
  bool ok = C.Equals(expect);

  if (!ok) {
    for (size_t i = 0; i < nbits; ++i) {
      const bool e = A.get(i) && B.get(i);
      if (C.get(i) != e) {
        std::cerr << "[Validate] mismatch i=" << i
                  << " A=" << int(A.get(i))
                  << " B=" << int(B.get(i))
                  << " C=" << int(C.get(i))
                  << " expect=" << int(e) << "\n";
        break;
      }
    }
  }

  uint8_t verdict = ok ? 1 : 0;
  for (int p = 1; p < world; ++p) {
    ctx->SendAsync(p, yacl::ByteContainerView(&verdict, 1), "open/verdict");
  }
  ctx->WaitLinkTaskFinish();
  return ok;
}

static std::vector<std::vector<EdgeRot>> BuildPrecomputedRotForAllEdges(int world,
                                                                        size_t nbits) {
  std::vector<std::vector<EdgeRot>> edge(world, std::vector<EdgeRot>(world));
  std::vector<BitVec> b_choice(world);
  for (int j = 0; j < world; ++j) b_choice[j] = BitVec::Rand(nbits);

  for (int i = 0; i < world; ++i) {
    for (int j = 0; j < world; ++j) {
      if (i == j) continue;

      edge[i][j].send.u0 = BitVec::Rand(nbits);
      edge[i][j].send.u1 = BitVec::Rand(nbits);

      edge[i][j].recv.choice = b_choice[j];

      BitVec u01 = BitVec::Xor(edge[i][j].send.u0, edge[i][j].send.u1);
      BitVec sel = BitVec::And(b_choice[j], u01);
      edge[i][j].recv.ub = BitVec::Xor(edge[i][j].send.u0, sel);
    }
  }
  return edge;
}

struct StatSnap {
  uint64_t sent = 0;
  uint64_t recv = 0;
};

static inline StatSnap TakeSnap(const std::shared_ptr<yacl::link::Context>& ctx) {
  auto st = ctx->GetStats();
  StatSnap s;
  s.sent = static_cast<uint64_t>(st->sent_bytes.load());
  s.recv = static_cast<uint64_t>(st->recv_bytes.load());
  return s;
}

static void GenOnlyRank(int rank,
                        const std::shared_ptr<yacl::link::Context>& ctx,
                        const std::vector<std::vector<EdgeRot>>& edge,
                        size_t ntriples,
                        BitTripleShare* out_share) {
  const int world = ctx->WorldSize();
  std::vector<std::unique_ptr<RotSendBits>> rot_send(world);
  std::vector<std::unique_ptr<RotRecvBits>> rot_recv(world);

  for (int peer = 0; peer < world; ++peer) {
    if (peer == rank) continue;

    {
      auto p = std::make_unique<RotSendBits>();
      p->u0 = edge[rank][peer].send.u0;
      p->u1 = edge[rank][peer].send.u1;
      rot_send[peer] = std::move(p);
    }
    {
      auto p = std::make_unique<RotRecvBits>();
      p->choice = edge[peer][rank].recv.choice;
      p->ub     = edge[peer][rank].recv.ub;
      rot_recv[peer] = std::move(p);
    }
  }

  *out_share = GenNPartyBitTriplesFromPrecomputedRot(ctx, ntriples, rot_send, rot_recv);
}

static void ValidateOnlyRank(int rank,
                             const std::shared_ptr<yacl::link::Context>& ctx,
                             const BitTripleShare* share,
                             uint8_t* ok_out) {
  (void)rank;
  bool ok = ValidateTriplesOpenToRank0(ctx, *share);
  *ok_out = ok ? 1 : 0;
}

int main(int argc, char** argv) {
  size_t world_sz = 15;
  size_t ntriples = 1<<26;

  if (argc >= 2) { world_sz = std::stoi(argv[1]);
}
  if (argc >= 3) { ntriples = static_cast<size_t>(std::stoull(argv[2]));
}

  YACL_ENFORCE(world_sz >= 2, "world must be >= 2");
  std::cout << "world=" << world_sz << " ntriples=" << ntriples << "\n";

  auto ctxs = yacl::link::test::SetupWorld(world_sz);
  auto edge = BuildPrecomputedRotForAllEdges((int)world_sz, ntriples);

  std::vector<BitTripleShare> shares(world_sz);

  std::vector<StatSnap> snap0(world_sz);
  std::vector<StatSnap> snap1(world_sz);
  for (size_t r = 0; r < world_sz; ++r) snap0[r] = TakeSnap(ctxs[r]);

  auto t0 = std::chrono::high_resolution_clock::now();

  {
    std::vector<std::thread> ths;
    ths.reserve(world_sz);
    for (size_t r = 0; r < world_sz; ++r) {
      ths.emplace_back([&, r]() { GenOnlyRank((int)r, ctxs[r], edge, ntriples, &shares[r]); });
    }
    for (auto& t : ths) t.join();
  }

  auto t1 = std::chrono::high_resolution_clock::now();
  for (size_t r = 0; r < world_sz; ++r) snap1[r] = TakeSnap(ctxs[r]);

  std::chrono::duration<double> gen_sec = t1 - t0;

  uint64_t gen_sent = 0;
  for (size_t r = 0; r < world_sz; ++r) {
    gen_sent += (snap1[r].sent - snap0[r].sent);
  }

  auto bytesToMB = [](uint64_t bytes) -> double {
    return static_cast<double>(bytes) / (1024.0 * 1024.0);
  };

  std::cout << "Generation time: " << gen_sec.count() << " seconds.\n";
  std::cout << "Generation communication: "<< bytesToMB(gen_sent) << " MB\n";

  std::vector<uint8_t> val_ok(world_sz, 0);
  {
    std::vector<std::thread> ths;
    ths.reserve(world_sz);
    for (size_t r = 0; r < world_sz; ++r) {
      ths.emplace_back([&, r]() {
        ValidateOnlyRank((int)r, ctxs[r], &shares[r], &val_ok[r]);
      });
    }
    for (auto& t : ths) t.join();
  }

  bool all_ok = true;
  for (size_t r = 0; r < world_sz; ++r) all_ok &= (val_ok[r] != 0);

  if (!all_ok) {
    std::cerr << "Validation failed on some ranks.\n";
    return 1;
  }
  std::cout << "[OK] triples validated (validation not counted in generation time/comm)\n";
  return 0;
}
