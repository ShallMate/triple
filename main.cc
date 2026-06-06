#include <chrono>
#include <cstdlib>
#include <cstdint>
#include <exception>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "coproto/Socket/LocalAsyncSock.h"
#include "coproto/coproto.h"
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/block.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "libOTe/Triple/SilentOtTriple/SilentOtTriple.h"
#include "libOTe/Triple/Foleage/FoleageTriple.h"
#include "libOTe/TwoChooseOne/ConfigureCode.h"
#include "libOTe/TwoChooseOne/TcoOtDefines.h"

namespace {

struct Config {
  enum class Method { SilentOtTriple, FoleageTriple, All };
  enum class Sec { SemiHonest, Malicious, All };
  std::uint64_t n = 1ULL << 20;
  Method method = Method::All;
  Sec sec = Sec::All;
  bool only_one_code = false;
  osuCrypto::MultType code = osuCrypto::MultType::ExConv7x24;
};

struct NetStats {
  std::uint64_t sent = 0;
  std::uint64_t recv = 0;
};

struct RunStats {
  double seconds = 0.0;
  NetStats party0;
  NetStats party1;
  std::uint64_t checked = 0;
};

double BytesToMB(std::uint64_t bytes) {
  return static_cast<double>(bytes) / (1024.0 * 1024.0);
}

void Require(bool cond, const std::string& msg) {
  if (!cond) {
    throw std::runtime_error(msg);
  }
}

std::string SecToString(osuCrypto::SilentSecType sec) {
  switch (sec) {
    case osuCrypto::SilentSecType::SemiHonest:
      return "semi-honest";
    case osuCrypto::SilentSecType::Malicious:
      return "malicious";
  }
  return "unknown";
}

std::string ConfigSecToString(Config::Sec sec) {
  switch (sec) {
    case Config::Sec::SemiHonest:
      return "semi-honest";
    case Config::Sec::Malicious:
      return "malicious";
    case Config::Sec::All:
      return "all";
  }
  return "unknown";
}

std::string MethodToString(Config::Method method) {
  switch (method) {
    case Config::Method::SilentOtTriple:
      return "SilentOtTriple";
    case Config::Method::FoleageTriple:
      return "FoleageTriple";
    case Config::Method::All:
      return "all";
  }
  return "unknown";
}

std::string CodeToString(osuCrypto::MultType code) {
  switch (code) {
    case osuCrypto::MultType::QuasiCyclic:
      return "QuasiCyclic";
    case osuCrypto::MultType::ExAcc7:
      return "ExAcc7";
    case osuCrypto::MultType::ExAcc11:
      return "ExAcc11";
    case osuCrypto::MultType::ExAcc21:
      return "ExAcc21";
    case osuCrypto::MultType::ExAcc40:
      return "ExAcc40";
    case osuCrypto::MultType::ExConv7x24:
      return "ExConv7x24";
    case osuCrypto::MultType::ExConv21x24:
      return "ExConv21x24";
    case osuCrypto::MultType::Tungsten:
      return "Tungsten";
  }
  return "unknown";
}

osuCrypto::MultType ParseCode(const std::string& code) {
  if (code == "qc" || code == "quasi" || code == "QuasiCyclic") {
    return osuCrypto::MultType::QuasiCyclic;
  }
  if (code == "exacc7" || code == "ExAcc7") {
    return osuCrypto::MultType::ExAcc7;
  }
  if (code == "exacc11" || code == "ExAcc11") {
    return osuCrypto::MultType::ExAcc11;
  }
  if (code == "exacc21" || code == "ExAcc21") {
    return osuCrypto::MultType::ExAcc21;
  }
  if (code == "exacc40" || code == "ExAcc40") {
    return osuCrypto::MultType::ExAcc40;
  }
  if (code == "exconv7" || code == "ExConv7x24") {
    return osuCrypto::MultType::ExConv7x24;
  }
  if (code == "exconv21" || code == "ExConv21x24") {
    return osuCrypto::MultType::ExConv21x24;
  }
  if (code == "tungsten" || code == "Tungsten") {
    return osuCrypto::MultType::Tungsten;
  }
  throw std::runtime_error("Unsupported --code value: " + code);
}

Config::Method ParseMethod(const std::string& method) {
  if (method == "all") {
    return Config::Method::All;
  }
  if (method == "silentot" || method == "silent_ot" ||
      method == "silentottriple" || method == "SilentOtTriple") {
    return Config::Method::SilentOtTriple;
  }
  if (method == "foleage" || method == "foliage" ||
      method == "foleagetriple" || method == "FoleageTriple") {
    return Config::Method::FoleageTriple;
  }
  throw std::runtime_error("Unsupported --method value: " + method);
}

std::vector<Config::Method> MethodList(Config::Method method) {
  if (method == Config::Method::SilentOtTriple) {
    return {Config::Method::SilentOtTriple};
  }
  if (method == Config::Method::FoleageTriple) {
    return {Config::Method::FoleageTriple};
  }
  return {Config::Method::SilentOtTriple, Config::Method::FoleageTriple};
}

std::vector<osuCrypto::MultType> DefaultCodes() {
  return {
      osuCrypto::MultType::ExAcc7,
      osuCrypto::MultType::ExAcc11,
      osuCrypto::MultType::ExAcc21,
      osuCrypto::MultType::ExAcc40,
      osuCrypto::MultType::ExConv7x24,
      osuCrypto::MultType::ExConv21x24,
      osuCrypto::MultType::QuasiCyclic,
      osuCrypto::MultType::Tungsten,
  };
}

std::vector<osuCrypto::SilentSecType> SecList(Config::Sec sec) {
  if (sec == Config::Sec::SemiHonest) {
    return {osuCrypto::SilentSecType::SemiHonest};
  }
  if (sec == Config::Sec::Malicious) {
    return {osuCrypto::SilentSecType::Malicious};
  }
  return {osuCrypto::SilentSecType::SemiHonest,
          osuCrypto::SilentSecType::Malicious};
}

void PrintUsage(const char* prog) {
  std::cout << "Usage: " << prog
            << " [--n N] [--method all|silentot|foleage]"
               " [--sec semi|mal|all]"
               " [--code all|exacc7|exacc11|exacc21|exacc40|exconv7|exconv21|qc|tungsten]\n";
}

Config ParseArgs(int argc, char** argv) {
  Config cfg;
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    if (arg == "--n") {
      Require(i + 1 < argc, "Missing value for --n");
      cfg.n = std::stoull(argv[++i]);
      Require(cfg.n > 0, "--n must be > 0");
    } else if (arg == "--method") {
      Require(i + 1 < argc, "Missing value for --method");
      cfg.method = ParseMethod(argv[++i]);
    } else if (arg == "--sec") {
      Require(i + 1 < argc, "Missing value for --sec");
      const std::string val = argv[++i];
      if (val == "semi" || val == "semi-honest") {
        cfg.sec = Config::Sec::SemiHonest;
      } else if (val == "mal" || val == "malicious") {
        cfg.sec = Config::Sec::Malicious;
      } else if (val == "all") {
        cfg.sec = Config::Sec::All;
      } else {
        throw std::runtime_error("Unsupported --sec value: " + val);
      }
    } else if (arg == "--mal") {
      cfg.sec = Config::Sec::Malicious;
    } else if (arg == "--code") {
      Require(i + 1 < argc, "Missing value for --code");
      const std::string val = argv[++i];
      if (val == "all") {
        cfg.only_one_code = false;
      } else {
        cfg.code = ParseCode(val);
        cfg.only_one_code = true;
      }
    } else if (arg == "--help" || arg == "-h") {
      PrintUsage(argv[0]);
      std::exit(0);
    } else {
      throw std::runtime_error("Unknown argument: " + arg);
    }
  }
  return cfg;
}

osuCrypto::block LastBlockMask(std::uint64_t nbits) {
  const std::uint64_t rem = nbits & 127;
  if (rem == 0) {
    return osuCrypto::block(~0ULL, ~0ULL);
  }
  if (rem < 64) {
    const std::uint64_t lo = (1ULL << rem) - 1;
    return osuCrypto::block(0, lo);
  }
  if (rem == 64) {
    return osuCrypto::block(0, ~0ULL);
  }
  const std::uint64_t hi = (1ULL << (rem - 64)) - 1;
  return osuCrypto::block(hi, ~0ULL);
}

void MaskTail(std::vector<osuCrypto::block>* v, std::uint64_t nbits) {
  if (!v->empty()) {
    v->back() &= LastBlockMask(nbits);
  }
}

bool ValidateTriples(const std::vector<osuCrypto::block>& a0,
                     const std::vector<osuCrypto::block>& b0,
                     const std::vector<osuCrypto::block>& c0,
                     const std::vector<osuCrypto::block>& a1,
                     const std::vector<osuCrypto::block>& b1,
                     const std::vector<osuCrypto::block>& c1,
                     std::uint64_t ntriples) {
  Require(a0.size() == b0.size() && a0.size() == c0.size(),
          "party0 output size mismatch");
  Require(a1.size() == b1.size() && a1.size() == c1.size(),
          "party1 output size mismatch");
  Require(a0.size() == a1.size(), "party output size mismatch");

  const auto tail_mask = LastBlockMask(ntriples);
  for (std::size_t i = 0; i < a0.size(); ++i) {
    const auto a = a0[i] ^ a1[i];
    const auto b = b0[i] ^ b1[i];
    auto c = c0[i] ^ c1[i];
    auto expect = a & b;
    if (i + 1 == a0.size()) {
      c &= tail_mask;
      expect &= tail_mask;
    }
    if (!(c == expect)) {
      return false;
    }
  }
  return true;
}

RunStats RunSilentOtTriple(std::uint64_t ntriples,
                           osuCrypto::SilentSecType sec,
                           osuCrypto::MultType code) {
  using namespace osuCrypto;

  const std::uint64_t blocks = (ntriples + 127) / 128;
  std::vector<block> a0(blocks), b0(blocks), c0(blocks);
  std::vector<block> a1(blocks), b1(blocks), c1(blocks);
  NetStats net0;
  NetStats net1;
  std::exception_ptr ep0;
  std::exception_ptr ep1;

  auto sockets = coproto::LocalAsyncSocket::makePair();
  const auto begin = std::chrono::steady_clock::now();

  std::thread party0([&, sock = std::move(sockets[0])]() mutable {
    try {
      PRNG prng(sysRandomSeed());
      SilentOtTriple triple;
      triple.mLpnMultType = code;
      triple.init(0, ntriples, sec, SilentOtTriple::Type::Triple);
      triple.mLpnMultType = code;
      coproto::sync_wait(triple.genBaseOts(prng, sock));
      coproto::sync_wait(triple.expand(a0, b0, c0, prng, sock));
      coproto::sync_wait(sock.flush());
      net0.sent = sock.bytesSent();
      net0.recv = sock.bytesReceived();
    } catch (...) {
      ep0 = std::current_exception();
    }
  });

  std::thread party1([&, sock = std::move(sockets[1])]() mutable {
    try {
      PRNG prng(sysRandomSeed());
      SilentOtTriple triple;
      triple.mLpnMultType = code;
      triple.init(1, ntriples, sec, SilentOtTriple::Type::Triple);
      triple.mLpnMultType = code;
      coproto::sync_wait(triple.genBaseOts(prng, sock));
      coproto::sync_wait(triple.expand(a1, b1, c1, prng, sock));
      coproto::sync_wait(sock.flush());
      net1.sent = sock.bytesSent();
      net1.recv = sock.bytesReceived();
    } catch (...) {
      ep1 = std::current_exception();
    }
  });

  party0.join();
  party1.join();

  if (ep0) {
    std::rethrow_exception(ep0);
  }
  if (ep1) {
    std::rethrow_exception(ep1);
  }

  MaskTail(&a0, ntriples);
  MaskTail(&b0, ntriples);
  MaskTail(&c0, ntriples);
  MaskTail(&a1, ntriples);
  MaskTail(&b1, ntriples);
  MaskTail(&c1, ntriples);
  Require(ValidateTriples(a0, b0, c0, a1, b1, c1, ntriples),
          "triple validation failed");

  const auto end = std::chrono::steady_clock::now();
  return RunStats{
      .seconds = std::chrono::duration<double>(end - begin).count(),
      .party0 = net0,
      .party1 = net1,
      .checked = ntriples,
  };
}

#ifdef ENABLE_FOLEAGE
RunStats RunFoleageTriple(std::uint64_t ntriples) {
  using namespace osuCrypto;

  const std::uint64_t blocks = (ntriples + 127) / 128;
  std::vector<block> a0(blocks), b0(blocks), c0(blocks);
  std::vector<block> a1(blocks), b1(blocks), c1(blocks);
  NetStats net0;
  NetStats net1;
  std::exception_ptr ep0;
  std::exception_ptr ep1;

  auto sockets = coproto::LocalAsyncSocket::makePair();
  const auto begin = std::chrono::steady_clock::now();

  std::thread party0([&, sock = std::move(sockets[0])]() mutable {
    try {
      PRNG prng(sysRandomSeed());
      FoleageTriple triple;
      triple.init(0, ntriples);
      coproto::sync_wait(triple.genBaseOts(prng, sock));
      coproto::sync_wait(triple.expand(a0, b0, c0, prng, sock));
      coproto::sync_wait(sock.flush());
      net0.sent = sock.bytesSent();
      net0.recv = sock.bytesReceived();
    } catch (...) {
      ep0 = std::current_exception();
    }
  });

  std::thread party1([&, sock = std::move(sockets[1])]() mutable {
    try {
      PRNG prng(sysRandomSeed());
      FoleageTriple triple;
      triple.init(1, ntriples);
      coproto::sync_wait(triple.genBaseOts(prng, sock));
      coproto::sync_wait(triple.expand(a1, b1, c1, prng, sock));
      coproto::sync_wait(sock.flush());
      net1.sent = sock.bytesSent();
      net1.recv = sock.bytesReceived();
    } catch (...) {
      ep1 = std::current_exception();
    }
  });

  party0.join();
  party1.join();

  if (ep0) {
    std::rethrow_exception(ep0);
  }
  if (ep1) {
    std::rethrow_exception(ep1);
  }

  MaskTail(&a0, ntriples);
  MaskTail(&b0, ntriples);
  MaskTail(&c0, ntriples);
  MaskTail(&a1, ntriples);
  MaskTail(&b1, ntriples);
  MaskTail(&c1, ntriples);
  Require(ValidateTriples(a0, b0, c0, a1, b1, c1, ntriples),
          "triple validation failed");

  const auto end = std::chrono::steady_clock::now();
  return RunStats{
      .seconds = std::chrono::duration<double>(end - begin).count(),
      .party0 = net0,
      .party1 = net1,
      .checked = ntriples,
  };
}
#endif

void PrintStats(const std::string& label, const RunStats& stats) {
  std::cout << "[" << label << "]\n";
  std::cout << "  time: " << stats.seconds << " s\n";
  std::cout << "  party0 sent/recv: " << BytesToMB(stats.party0.sent) << " / "
            << BytesToMB(stats.party0.recv) << " MB\n";
  std::cout << "  party1 sent/recv: " << BytesToMB(stats.party1.sent) << " / "
            << BytesToMB(stats.party1.recv) << " MB\n";
  std::cout << "  total communication: "
            << BytesToMB(stats.party0.sent + stats.party0.recv) << " MB\n";
  std::cout << "  checked: " << stats.checked << " triples\n";
}

void PrintSkipped(const std::string& label, const std::string& reason) {
  std::cout << "[" << label << "]\n";
  std::cout << "  skipped: " << reason << "\n";
}

}  // namespace

int main(int argc, char** argv) {
  try {
    const auto cfg = ParseArgs(argc, argv);
    const auto methods = MethodList(cfg.method);
    const auto secs = SecList(cfg.sec);
    const auto codes = cfg.only_one_code ? std::vector{cfg.code}
                                         : DefaultCodes();

    std::cout << "libOTE triple generator test\n";
    std::cout << "  n=" << cfg.n << "\n";
    std::cout << "  method=" << MethodToString(cfg.method) << "\n";
    std::cout << "  sec=" << ConfigSecToString(cfg.sec) << "\n";
    std::cout << "  code=" << (cfg.only_one_code ? CodeToString(cfg.code)
                                                 : std::string("all"))
              << "\n";

    for (const auto method : methods) {
      if (method == Config::Method::SilentOtTriple) {
        for (const auto sec : secs) {
          for (const auto code : codes) {
            const auto label = MethodToString(method) + " / " +
                               SecToString(sec) + " / " +
                               CodeToString(code);
            try {
              const auto stats = RunSilentOtTriple(cfg.n, sec, code);
              PrintStats(label, stats);
            } catch (const std::exception& e) {
              PrintSkipped(label, e.what());
            }
          }
        }
      } else if (method == Config::Method::FoleageTriple) {
#ifdef ENABLE_FOLEAGE
        try {
          const auto stats = RunFoleageTriple(cfg.n);
          PrintStats(MethodToString(method), stats);
        } catch (const std::exception& e) {
          PrintSkipped(MethodToString(method), e.what());
        }
#else
        PrintSkipped(MethodToString(method),
                     "ENABLE_FOLEAGE is not defined in this libOTE build");
#endif
      }
    }

    std::cout << "matrix completed\n";
    return 0;
  } catch (const std::exception& e) {
    std::cerr << "error: " << e.what() << "\n";
    PrintUsage(argv[0]);
    return 1;
  }
}
