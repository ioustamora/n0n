use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use n0n::utils::*;
use tempfile::{NamedTempFile, tempdir};
use std::fs;
use std::path::Path;

fn sha256_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha256");
    
    let data_sizes = [
        (64, "64B"),
        (1024, "1KB"),
        (4096, "4KB"),
        (16384, "16KB"),
        (65536, "64KB"),
        (262144, "256KB"),
        (1048576, "1MB"),
        (10485760, "10MB"),
    ];
    
    for (size, label) in data_sizes.iter() {
        let data = vec![42u8; *size];
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::new("compute", label), size, |b, &_size| {
            b.iter(|| {
                black_box(compute_sha256(&data))
            })
        });
    }
    group.finish();
}

fn base64_encoding_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("base64_encoding");
    
    let data_sizes = [
        (64, "64B"),
        (1024, "1KB"),
        (4096, "4KB"),
        (16384, "16KB"),
        (65536, "64KB"),
        (262144, "256KB"),
        (1048576, "1MB"),
    ];
    
    for (size, label) in data_sizes.iter() {
        let data = vec![42u8; *size];
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::new("encode", label), size, |b, &_size| {
            b.iter(|| {
                black_box(encode_base64(&data))
            })
        });
    }
    group.finish();
}

fn base64_decoding_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("base64_decoding");
    
    let data_sizes = [
        (64, "64B"),
        (1024, "1KB"),
        (4096, "4KB"),
        (16384, "16KB"),
        (65536, "64KB"),
        (262144, "256KB"),
        (1048576, "1MB"),
    ];
    
    for (size, label) in data_sizes.iter() {
        let data = vec![42u8; *size];
        let encoded = encode_base64(&data);
        
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::new("decode", label), size, |b, &_size| {
            b.iter(|| {
                black_box(decode_base64(&encoded).unwrap())
            })
        });
    }
    group.finish();
}

fn base64_roundtrip_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("base64_roundtrip");
    
    let data_sizes = [
        (1024, "1KB"),
        (16384, "16KB"),
        (65536, "64KB"),
        (262144, "256KB"),
    ];
    
    for (size, label) in data_sizes.iter() {
        let data = vec![42u8; *size];
        
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::new("encode_decode", label), size, |b, &_size| {
            b.iter(|| {
                let encoded = encode_base64(&data);
                let decoded = decode_base64(&encoded).unwrap();
                black_box(decoded)
            })
        });
    }
    group.finish();
}

fn file_operations_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("file_operations");
    
    let file_sizes = [
        (1024, "1KB"),
        (10240, "10KB"),
        (102400, "100KB"),
        (1048576, "1MB"),
    ];
    
    for (size, label) in file_sizes.iter() {
        let temp_file = NamedTempFile::new().unwrap();
        let data = vec![42u8; *size];
        fs::write(temp_file.path(), &data).unwrap();
        
        group.throughput(Throughput::Bytes(*size as u64));
        
        // Benchmark file size retrieval
        group.bench_with_input(BenchmarkId::new("get_file_size", label), size, |b, &_size| {
            b.iter(|| {
                black_box(get_file_size(temp_file.path()).unwrap())
            })
        });
        
        // Benchmark file reading
        group.bench_with_input(BenchmarkId::new("read_file_to_bytes", label), size, |b, &_size| {
            b.iter(|| {
                black_box(read_file_to_bytes(temp_file.path()).unwrap())
            })
        });
    }
    group.finish();
}

fn file_writing_benchmark(c: &mut Criterion) {
    let temp_dir = tempdir().unwrap();
    
    let mut group = c.benchmark_group("file_writing");
    
    let data_sizes = [
        (1024, "1KB"),
        (10240, "10KB"),
        (102400, "100KB"),
        (1048576, "1MB"),
    ];
    
    for (size, label) in data_sizes.iter() {
        let data = vec![42u8; *size];
        
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::new("write_bytes_to_file", label), size, |b, &_size| {
            let mut counter = 0;
            b.iter(|| {
                let file_path = temp_dir.path().join(format!("test_{}.bin", counter));
                counter += 1;
                black_box(write_bytes_to_file(&file_path, &data).unwrap())
            })
        });
    }
    group.finish();
}

fn directory_operations_benchmark(c: &mut Criterion) {
    let temp_dir = tempdir().unwrap();
    
    c.bench_function("create_dir_if_not_exists", |b| {
        let mut counter = 0;
        b.iter(|| {
            let dir_path = temp_dir.path().join(format!("test_dir_{}", counter));
            counter += 1;
            black_box(create_dir_if_not_exists(&dir_path).unwrap())
        })
    });
}

fn key_parsing_benchmark(c: &mut Criterion) {
    let hex_key = "deadbeefcafebabe0123456789abcdef";
    let base64_key = encode_base64(&hex::decode(hex_key).unwrap());
    
    let mut group = c.benchmark_group("key_parsing");
    
    group.bench_function("parse_hex_key", |b| {
        b.iter(|| {
            black_box(parse_key_hex_or_b64(hex_key).unwrap())
        })
    });
    
    group.bench_function("parse_base64_key", |b| {
        b.iter(|| {
            black_box(parse_key_hex_or_b64(&base64_key).unwrap())
        })
    });
    
    group.finish();
}

fn chunk_estimation_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("chunk_estimation");
    
    let test_cases = [
        (1000, 100, "small_file_small_chunks"),
        (10000, 1000, "medium_file_medium_chunks"), 
        (100000, 8192, "large_file_standard_chunks"),
        (1000000, 65536, "very_large_file_large_chunks"),
    ];
    
    for (file_size, chunk_size, label) in test_cases.iter() {
        group.bench_with_input(BenchmarkId::new("estimate_chunks", label), file_size, |b, &file_size| {
            b.iter(|| {
                black_box(estimate_chunks(file_size, *chunk_size))
            })
        });
    }
    group.finish();
}

fn mixed_operations_benchmark(c: &mut Criterion) {
    let temp_file = NamedTempFile::new().unwrap();
    let original_data = vec![123u8; 65536]; // 64KB
    fs::write(temp_file.path(), &original_data).unwrap();
    
    let mut group = c.benchmark_group("mixed_operations");
    group.throughput(Throughput::Bytes(65536));
    
    // Benchmark a realistic workflow: read file, compute hash, encode to base64
    group.bench_function("read_hash_encode_workflow", |b| {
        b.iter(|| {
            let data = read_file_to_bytes(temp_file.path()).unwrap();
            let hash = compute_sha256(&data);
            let encoded = encode_base64(&data);
            black_box((hash, encoded))
        })
    });
    
    // Benchmark verification workflow: decode from base64, compute hash, verify
    let encoded_data = encode_base64(&original_data);
    let expected_hash = compute_sha256(&original_data);
    
    group.bench_function("decode_hash_verify_workflow", |b| {
        b.iter(|| {
            let decoded = decode_base64(&encoded_data).unwrap();
            let computed_hash = compute_sha256(&decoded);
            let verified = computed_hash == expected_hash;
            black_box(verified)
        })
    });
    
    group.finish();
}

fn error_handling_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("error_handling");
    
    // Benchmark error cases to ensure they don't have performance penalties
    group.bench_function("decode_invalid_base64", |b| {
        b.iter(|| {
            let result = decode_base64("invalid base64 data!");
            black_box(result.is_err())
        })
    });
    
    group.bench_function("get_size_nonexistent_file", |b| {
        b.iter(|| {
            let result = get_file_size(Path::new("/nonexistent/file/path"));
            black_box(result.is_err())
        })
    });
    
    group.bench_function("read_nonexistent_file", |b| {
        b.iter(|| {
            let result = read_file_to_bytes(Path::new("/nonexistent/file/path"));
            black_box(result.is_err())
        })
    });
    
    group.bench_function("parse_invalid_key", |b| {
        b.iter(|| {
            let result = parse_key_hex_or_b64("not a valid key!");
            black_box(result.is_err())
        })
    });
    
    group.finish();
}

fn concurrent_operations_benchmark(c: &mut Criterion) {
    use rayon::prelude::*;
    
    let temp_files: Vec<_> = (0..10).map(|i| {
        let temp_file = NamedTempFile::new().unwrap();
        let data = vec![(i as u8 + 42); 10240]; // 10KB each, different content
        fs::write(temp_file.path(), &data).unwrap();
        temp_file
    }).collect();
    
    let mut group = c.benchmark_group("concurrent_operations");
    
    group.bench_function("sequential_file_processing", |b| {
        b.iter(|| {
            let results: Vec<_> = temp_files.iter().map(|temp_file| {
                let data = read_file_to_bytes(temp_file.path()).unwrap();
                let hash = compute_sha256(&data);
                black_box(hash)
            }).collect();
            black_box(results)
        })
    });
    
    group.bench_function("parallel_file_processing", |b| {
        b.iter(|| {
            let results: Vec<_> = temp_files.par_iter().map(|temp_file| {
                let data = read_file_to_bytes(temp_file.path()).unwrap();
                let hash = compute_sha256(&data);
                black_box(hash)
            }).collect();
            black_box(results)
        })
    });
    
    group.finish();
}

criterion_group!(
    benches,
    sha256_benchmark,
    base64_encoding_benchmark,
    base64_decoding_benchmark,
    base64_roundtrip_benchmark,
    file_operations_benchmark,
    file_writing_benchmark,
    directory_operations_benchmark,
    key_parsing_benchmark,
    chunk_estimation_benchmark,
    mixed_operations_benchmark,
    error_handling_benchmark,
    concurrent_operations_benchmark
);
criterion_main!(benches);