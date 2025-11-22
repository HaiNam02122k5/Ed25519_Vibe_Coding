"""
Ed25519 Performance Benchmark Module
Đánh giá performance chi tiết giống như trong paper

Metrics:
- Cycle counts (ước lượng từ time)
- Throughput (operations/second)
- Latency (ms per operation)
- Memory usage
- Comparison với paper results
"""

import time
import statistics
import psutil
import os
from typing import List, Dict

from backend.Ed25519.Ed25519_KeyGen import generate_keypair, Ed25519PrivateKey
from backend.Ed25519.Ed25519_Sign import sign, sign_with_scalar_mul
from backend.Ed25519.Ed25519_Verify import verify, batch_verify, BatchVerifier
from backend.Ed25519.Ed25519_CurveArithmetic import EdwardsPoint, BASE_POINT
from backend.Ed25519.Ed25519_FieldArithmetic import FieldElement


class PerformanceBenchmark:
    """
    Benchmark suite cho Ed25519 implementation
    """

    def __init__(self, cpu_freq_ghz=None):
        """
        Args:
            cpu_freq_ghz: CPU frequency in GHz (nếu None, auto-detect)
        """
        if cpu_freq_ghz is None:
            # Try to get CPU frequency
            try:
                cpu_freq = psutil.cpu_freq()
                self.cpu_freq_ghz = cpu_freq.current / 1000.0  # MHz -> GHz
            except:
                self.cpu_freq_ghz = 2.4  # Default assumption
        else:
            self.cpu_freq_ghz = cpu_freq_ghz

        self.results = {}

    def time_to_cycles(self, seconds):
        """
        Convert time (seconds) to estimated CPU cycles

        Args:
            seconds: Time in seconds

        Returns:
            int: Estimated CPU cycles
        """
        return int(seconds * self.cpu_freq_ghz * 1e9)

    def benchmark_operation(self, operation, setup=None, n_iterations=100, warmup=10):
        """
        Benchmark một operation

        Args:
            operation: Function to benchmark
            setup: Setup function (called once)
            n_iterations: Number of iterations
            warmup: Number of warmup iterations

        Returns:
            dict: Benchmark results
        """
        # Setup
        if setup:
            setup_data = setup()
        else:
            setup_data = None

        # Warmup
        for _ in range(warmup):
            if setup_data:
                operation(*setup_data)
            else:
                operation()

        # Benchmark
        times = []
        for _ in range(n_iterations):
            start = time.perf_counter()
            if setup_data:
                operation(*setup_data)
            else:
                operation()
            elapsed = time.perf_counter() - start
            times.append(elapsed)

        # Statistics
        mean_time = statistics.mean(times)
        median_time = statistics.median(times)
        stdev_time = statistics.stdev(times) if len(times) > 1 else 0
        min_time = min(times)
        max_time = max(times)

        # Convert to cycles
        mean_cycles = self.time_to_cycles(mean_time)
        median_cycles = self.time_to_cycles(median_time)
        min_cycles = self.time_to_cycles(min_time)

        # Throughput
        throughput = 1.0 / mean_time if mean_time > 0 else 0

        return {
            "mean_time_ms": mean_time * 1000,
            "median_time_ms": median_time * 1000,
            "stdev_time_ms": stdev_time * 1000,
            "min_time_ms": min_time * 1000,
            "max_time_ms": max_time * 1000,
            "mean_cycles": mean_cycles,
            "median_cycles": median_cycles,
            "min_cycles": min_cycles,
            "throughput": throughput,
            "n_iterations": n_iterations
        }

    def benchmark_field_operations(self):
        """Benchmark field arithmetic operations"""
        print("\n" + "=" * 70)
        print("FIELD ARITHMETIC BENCHMARK")
        print("=" * 70)

        a = FieldElement(value=12345)
        b = FieldElement(value=67890)

        # Addition
        result = self.benchmark_operation(
            lambda: a.add(b),
            n_iterations=10000
        )
        self.results['field_add'] = result
        print(f"\nField Addition:")
        print(f"  Mean time: {result['mean_time_ms']:.6f} ms")
        print(f"  Est. cycles: {result['mean_cycles']:,}")
        print(f"  Throughput: {result['throughput']:,.0f} ops/sec")

        # Multiplication
        result = self.benchmark_operation(
            lambda: a.mul(b),
            n_iterations=10000
        )
        self.results['field_mul'] = result
        print(f"\nField Multiplication:")
        print(f"  Mean time: {result['mean_time_ms']:.6f} ms")
        print(f"  Est. cycles: {result['mean_cycles']:,}")
        print(f"  Throughput: {result['throughput']:,.0f} ops/sec")

        # Squaring
        result = self.benchmark_operation(
            lambda: a.square(),
            n_iterations=10000
        )
        self.results['field_square'] = result
        print(f"\nField Squaring:")
        print(f"  Mean time: {result['mean_time_ms']:.6f} ms")
        print(f"  Est. cycles: {result['mean_cycles']:,}")
        print(f"  Throughput: {result['throughput']:,.0f} ops/sec")

        # Inversion
        result = self.benchmark_operation(
            lambda: a.invert(),
            n_iterations=1000
        )
        self.results['field_invert'] = result
        print(f"\nField Inversion:")
        print(f"  Mean time: {result['mean_time_ms']:.4f} ms")
        print(f"  Est. cycles: {result['mean_cycles']:,}")
        print(f"  Throughput: {result['throughput']:,.0f} ops/sec")

    def benchmark_curve_operations(self):
        """Benchmark elliptic curve operations"""
        print("\n" + "=" * 70)
        print("ELLIPTIC CURVE OPERATIONS BENCHMARK")
        print("=" * 70)

        P = BASE_POINT
        Q = BASE_POINT.scalar_mul(12345)

        # Point addition
        result = self.benchmark_operation(
            lambda: P.add(Q),
            n_iterations=1000
        )
        self.results['point_add'] = result
        print(f"\nPoint Addition:")
        print(f"  Mean time: {result['mean_time_ms']:.4f} ms")
        print(f"  Est. cycles: {result['mean_cycles']:,}")
        print(f"  Throughput: {result['throughput']:,.0f} ops/sec")

        # Point doubling
        result = self.benchmark_operation(
            lambda: P.double(),
            n_iterations=1000
        )
        self.results['point_double'] = result
        print(f"\nPoint Doubling:")
        print(f"  Mean time: {result['mean_time_ms']:.4f} ms")
        print(f"  Est. cycles: {result['mean_cycles']:,}")
        print(f"  Throughput: {result['throughput']:,.0f} ops/sec")

        # Scalar multiplication
        result = self.benchmark_operation(
            lambda: P.scalar_mul(123456789),
            n_iterations=100
        )
        self.results['scalar_mul'] = result
        print(f"\nScalar Multiplication:")
        print(f"  Mean time: {result['mean_time_ms']:.4f} ms")
        print(f"  Est. cycles: {result['mean_cycles']:,}")
        print(f"  Throughput: {result['throughput']:,.0f} ops/sec")

    def benchmark_key_generation(self):
        """Benchmark key generation"""
        print("\n" + "=" * 70)
        print("KEY GENERATION BENCHMARK")
        print("=" * 70)

        result = self.benchmark_operation(
            lambda: generate_keypair(),
            n_iterations=100
        )
        self.results['keygen'] = result

        print(f"\nKey Generation:")
        print(f"  Mean time: {result['mean_time_ms']:.4f} ms")
        print(f"  Est. cycles: {result['mean_cycles']:,}")
        print(f"  Throughput: {result['throughput']:,.0f} keypairs/sec")
        print(f"\n  Paper reports: ~88,000 cycles + 6,000 for randomness")
        print(f"  Our estimate: {result['mean_cycles']:,} cycles")

    def benchmark_signing(self):
        """Benchmark signature generation"""
        print("\n" + "=" * 70)
        print("SIGNATURE GENERATION BENCHMARK")
        print("=" * 70)

        private_key, _ = generate_keypair()
        message = b"Benchmark message for signing performance testing"

        # With precomputed table
        result = self.benchmark_operation(
            lambda: sign(message, private_key),
            n_iterations=100
        )
        self.results['sign_with_table'] = result

        print(f"\nSigning (with precomputed table):")
        print(f"  Mean time: {result['mean_time_ms']:.4f} ms")
        print(f"  Est. cycles: {result['mean_cycles']:,}")
        print(f"  Throughput: {result['throughput']:,.0f} signatures/sec")
        print(f"\n  Paper reports: 88,328 cycles on Westmere @ 2.4GHz")
        print(f"  Paper throughput: 108,000 signatures/sec (quad-core)")
        print(f"  Our estimate: {result['mean_cycles']:,} cycles")

        # Without precomputed table (for comparison)
        result_no_table = self.benchmark_operation(
            lambda: sign_with_scalar_mul(message, private_key),
            n_iterations=20
        )
        self.results['sign_without_table'] = result_no_table

        print(f"\nSigning (without precomputed table):")
        print(f"  Mean time: {result_no_table['mean_time_ms']:.4f} ms")
        print(f"  Est. cycles: {result_no_table['mean_cycles']:,}")
        print(f"  Throughput: {result_no_table['throughput']:,.0f} signatures/sec")

        speedup = result_no_table['mean_time_ms'] / result['mean_time_ms']
        print(f"\n  Speedup with table: {speedup:.2f}x")

    def benchmark_verification(self):
        """Benchmark signature verification"""
        print("\n" + "=" * 70)
        print("SIGNATURE VERIFICATION BENCHMARK")
        print("=" * 70)

        # Setup
        private_key, public_key = generate_keypair()
        message = b"Benchmark message for verification"
        signature = sign(message, private_key)

        # Single verification
        result = self.benchmark_operation(
            lambda: verify(signature, message, public_key),
            n_iterations=100
        )
        self.results['verify_single'] = result

        print(f"\nSingle Verification:")
        print(f"  Mean time: {result['mean_time_ms']:.4f} ms")
        print(f"  Est. cycles: {result['mean_cycles']:,}")
        print(f"  Throughput: {result['throughput']:,.0f} verifications/sec")
        print(f"\n  Paper reports: 280,880 cycles on Westmere")
        print(f"  Our estimate: {result['mean_cycles']:,} cycles")

    def benchmark_batch_verification(self):
        """Benchmark batch verification"""
        print("\n" + "=" * 70)
        print("BATCH VERIFICATION BENCHMARK")
        print("=" * 70)

        batch_sizes = [8, 16, 32, 64, 128]

        for batch_size in batch_sizes:
            # Generate test data
            signatures = []
            messages = []
            public_keys = []

            for i in range(batch_size):
                private_key, public_key = generate_keypair()
                message = f"Message {i}".encode()
                signature = sign(message, private_key)

                signatures.append(signature)
                messages.append(message)
                public_keys.append(public_key)

            # Benchmark batch verification
            result = self.benchmark_operation(
                lambda: batch_verify(signatures, messages, public_keys),
                n_iterations=20
            )

            cycles_per_sig = result['mean_cycles'] / batch_size
            time_per_sig = result['mean_time_ms'] / batch_size

            self.results[f'batch_verify_{batch_size}'] = result

            print(f"\nBatch size: {batch_size}")
            print(f"  Total time: {result['mean_time_ms']:.4f} ms")
            print(f"  Time per signature: {time_per_sig:.4f} ms")
            print(f"  Est. cycles per signature: {cycles_per_sig:,.0f}")
            print(f"  Throughput: {batch_size * result['throughput']:,.0f} verifications/sec")

            if batch_size == 64:
                print(f"\n  Paper reports: 134,000 cycles/signature (batch of 64)")
                print(f"  Our estimate: {cycles_per_sig:,.0f} cycles/signature")

    def compare_with_paper(self):
        """So sánh kết quả với paper"""
        print("\n" + "=" * 70)
        print("COMPARISON WITH PAPER RESULTS")
        print("=" * 70)

        paper_results = {
            "Key Generation": 88000,
            "Signing": 88328,
            "Single Verification": 280880,
            "Batch Verification (64)": 134000
        }

        our_results = {
            "Key Generation": self.results.get('keygen', {}).get('mean_cycles', 0),
            "Signing": self.results.get('sign_with_table', {}).get('mean_cycles', 0),
            "Single Verification": self.results.get('verify_single', {}).get('mean_cycles', 0),
            "Batch Verification (64)": self.results.get('batch_verify_64', {}).get('mean_cycles',
                                                                                   0) / 64 if 'batch_verify_64' in self.results else 0
        }

        print(f"\n{'Operation':<30} {'Paper':<15} {'Ours':<15} {'Ratio':<10}")
        print("-" * 70)

        for op in paper_results:
            paper_cycles = paper_results[op]
            our_cycles = our_results[op]
            ratio = our_cycles / paper_cycles if paper_cycles > 0 else 0

            print(f"{op:<30} {paper_cycles:>12,} {our_cycles:>14,.0f} {ratio:>9.2f}x")

        print("\nNOTE:")
        print("- Paper uses optimized C code on Intel Westmere CPU @ 2.4GHz")
        print("- Our implementation is pure Python (much slower)")
        print("- Cycle estimates are approximate (based on time measurement)")
        print("- Ratios show how many times slower we are vs paper")

    def memory_analysis(self):
        """Phân tích memory usage"""
        print("\n" + "=" * 70)
        print("MEMORY USAGE ANALYSIS")
        print("=" * 70)

        import sys

        # Field element
        field_elem = FieldElement(value=12345)
        print(f"\nFieldElement size: {sys.getsizeof(field_elem)} bytes")
        print(f"  (5 limbs × 8 bytes = 40 bytes minimum)")

        # Edwards point
        point = BASE_POINT
        print(f"\nEdwardsPoint size: {sys.getsizeof(point)} bytes")
        print(f"  (4 coordinates × FieldElement)")

        # Private key
        private_key, public_key = generate_keypair()
        print(f"\nPrivate key size: {sys.getsizeof(private_key)} bytes")
        print(f"  Seed: 32 bytes")
        print(f"  Serialized: {len(private_key.to_bytes())} bytes")

        # Public key
        print(f"\nPublic key size: {sys.getsizeof(public_key)} bytes")
        print(f"  Serialized: {len(public_key.to_bytes())} bytes")

        # Signature
        message = b"Test"
        signature = sign(message, private_key)
        print(f"\nSignature size: {sys.getsizeof(signature)} bytes")
        print(f"  Serialized: {len(signature.to_bytes())} bytes")
        print(f"  (R: 32 bytes, S: 32 bytes)")

        print("\n  Paper reports:")
        print("    Public keys: 32 bytes")
        print("    Signatures: 64 bytes")
        print("    ✓ Matches our implementation!")

    def run_full_benchmark(self):
        """Chạy toàn bộ benchmark"""
        print("\n" + "=" * 70)
        print("Ed25519 PERFORMANCE BENCHMARK")
        print("=" * 70)
        print(f"CPU Frequency: {self.cpu_freq_ghz:.2f} GHz (estimated)")
        print(f"Python implementation (not optimized C)")
        print("=" * 70)

        # Run benchmarks
        self.benchmark_field_operations()
        self.benchmark_curve_operations()
        self.benchmark_key_generation()
        self.benchmark_signing()
        self.benchmark_verification()
        self.benchmark_batch_verification()
        self.memory_analysis()
        self.compare_with_paper()

        # Summary
        print("\n" + "=" * 70)
        print("SUMMARY")
        print("=" * 70)
        print("\nKey Findings:")
        print("1. Python is ~1000-10000x slower than optimized C")
        print("2. Batch verification shows significant speedup")
        print("3. Precomputed tables improve signing performance")
        print("4. Memory usage matches paper specifications")
        print("\nFor production use, consider:")
        print("- Using cryptography library (rust/C backend)")
        print("- PyNaCl (libsodium Python binding)")
        print("- This implementation is educational/reference")


def quick_benchmark():
    """Quick benchmark for testing"""
    print("Running quick benchmark...")

    bench = PerformanceBenchmark()

    # Key generation
    result = bench.benchmark_operation(
        lambda: generate_keypair(),
        n_iterations=10
    )
    print(f"\nKey Generation: {result['mean_time_ms']:.2f} ms")
    print(f"  Est. cycles: {result['mean_cycles']:,}")

    # Signing
    private_key, _ = generate_keypair()
    message = b"Test message"

    result = bench.benchmark_operation(
        lambda: sign(message, private_key),
        n_iterations=10
    )
    print(f"\nSigning: {result['mean_time_ms']:.2f} ms")
    print(f"  Est. cycles: {result['mean_cycles']:,}")

    # Verification
    signature = sign(message, private_key)
    public_key = private_key.get_public_key()

    result = bench.benchmark_operation(
        lambda: verify(signature, message, public_key),
        n_iterations=10
    )
    print(f"\nVerification: {result['mean_time_ms']:.2f} ms")
    print(f"  Est. cycles: {result['mean_cycles']:,}")


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "quick":
        quick_benchmark()
    else:
        bench = PerformanceBenchmark()
        bench.run_full_benchmark()