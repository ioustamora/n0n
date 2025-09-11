use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use n0n::chunk::*;
use n0n::utils::compute_sha256;
use tempfile::NamedTempFile;
use std::fs;
use std::time::Duration;

fn split_file_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("split_file");
    group.measurement_time(Duration::from_secs(10));
    
    // Test different file sizes
    let file_sizes = [
        (1024, "1KB"),
        (10240, "10KB"), 
        (102400, "100KB"),
        (1048576, "1MB"),
        (10485760, "10MB"),
    ];
    
    for (size, label) in file_sizes.iter() {
        let temp_file = NamedTempFile::new().unwrap();
        let data = vec![42u8; *size];
        fs::write(temp_file.path(), &data).unwrap();
        
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::new("split", label), size, |b, &_size| {
            b.iter(|| {
                black_box(split_file_into_chunks(temp_file.path(), 8192, "test.bin").unwrap())
            })
        });
    }
    group.finish();
}

fn chunk_size_comparison_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("chunk_size_comparison");
    
    // Fixed file size, different chunk sizes
    let temp_file = NamedTempFile::new().unwrap();
    let data = vec![42u8; 1048576]; // 1MB file
    fs::write(temp_file.path(), &data).unwrap();
    
    let chunk_sizes = [1024, 4096, 8192, 16384, 32768, 65536];
    
    for chunk_size in chunk_sizes.iter() {
        group.throughput(Throughput::Bytes(1048576));
        group.bench_with_input(BenchmarkId::new("split", chunk_size), chunk_size, |b, &chunk_size| {
            b.iter(|| {
                black_box(split_file_into_chunks(temp_file.path(), chunk_size, "test.bin").unwrap())
            })
        });
    }
    group.finish();
}

fn assemble_file_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("assemble_file");
    
    let file_sizes = [
        (10240, "10KB"),
        (102400, "100KB"), 
        (1048576, "1MB"),
    ];
    
    for (size, label) in file_sizes.iter() {
        let temp_file = NamedTempFile::new().unwrap();
        let data = vec![42u8; *size];
        fs::write(temp_file.path(), &data).unwrap();
        
        let chunks = split_file_into_chunks(temp_file.path(), 8192, "test.bin").unwrap();
        
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::new("assemble", label), size, |b, &_size| {
            b.iter(|| {
                black_box(assemble_file_from_chunks(&chunks).unwrap())
            })
        });
    }
    group.finish();
}

fn verify_chunk_integrity_benchmark(c: &mut Criterion) {
    let temp_file = NamedTempFile::new().unwrap();
    let data = vec![123u8; 102400]; // 100KB
    fs::write(temp_file.path(), &data).unwrap();
    
    let chunks = split_file_into_chunks(temp_file.path(), 4096, "test.bin").unwrap();
    let single_chunk = &chunks[0];
    
    c.bench_function("verify_single_chunk", |b| {
        b.iter(|| {
            black_box(verify_chunk_integrity(single_chunk).unwrap())
        })
    });
    
    c.bench_function("verify_all_chunks", |b| {
        b.iter(|| {
            for chunk in &chunks {
                black_box(verify_chunk_integrity(chunk).unwrap());
            }
        })
    });
}

fn verify_file_integrity_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify_file_integrity");
    
    let file_sizes = [
        (10240, "10KB"),
        (102400, "100KB"),
        (1048576, "1MB"),
    ];
    
    for (size, label) in file_sizes.iter() {
        let temp_file = NamedTempFile::new().unwrap();
        let data = vec![42u8; *size];
        fs::write(temp_file.path(), &data).unwrap();
        
        let chunks = split_file_into_chunks(temp_file.path(), 8192, "test.bin").unwrap();
        let assembled = assemble_file_from_chunks(&chunks).unwrap();
        
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::new("verify", label), size, |b, &_size| {
            b.iter(|| {
                black_box(verify_file_integrity(&chunks, &assembled).unwrap())
            })
        });
    }
    group.finish();
}

fn parallel_chunk_processing_benchmark(c: &mut Criterion) {
    use rayon::prelude::*;
    
    let temp_file = NamedTempFile::new().unwrap();
    let data = vec![42u8; 1048576]; // 1MB
    fs::write(temp_file.path(), &data).unwrap();
    
    let chunks = split_file_into_chunks(temp_file.path(), 4096, "test.bin").unwrap();
    
    let mut group = c.benchmark_group("parallel_processing");
    
    group.bench_function("sequential_verification", |b| {
        b.iter(|| {
            for chunk in &chunks {
                black_box(verify_chunk_integrity(chunk).unwrap());
            }
        })
    });
    
    group.bench_function("parallel_verification", |b| {
        b.iter(|| {
            chunks.par_iter().for_each(|chunk| {
                black_box(verify_chunk_integrity(chunk).unwrap());
            });
        })
    });
    
    group.finish();
}

fn sha256_computation_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha256_computation");
    
    // Test SHA256 computation on different data sizes
    let data_sizes = [
        (1024, "1KB"),
        (8192, "8KB"),
        (65536, "64KB"),
        (262144, "256KB"),
        (1048576, "1MB"),
    ];
    
    for (size, label) in data_sizes.iter() {
        let data = vec![42u8; *size];
        
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::new("compute_sha256", label), size, |b, &_size| {
            b.iter(|| {
                black_box(compute_sha256(&data))
            })
        });
    }
    group.finish();
}

fn chunk_metadata_creation_benchmark(c: &mut Criterion) {
    let temp_file = NamedTempFile::new().unwrap();
    let data = vec![123u8; 1048576]; // 1MB
    fs::write(temp_file.path(), &data).unwrap();
    
    let mut group = c.benchmark_group("chunk_metadata");
    
    // Compare different approaches to chunk metadata creation
    group.bench_function("with_parallel_hashing", |b| {
        b.iter(|| {
            black_box(split_file_into_chunks(temp_file.path(), 8192, "test.bin").unwrap())
        })
    });
    
    group.finish();
}

fn roundtrip_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("split_assemble_roundtrip");
    group.measurement_time(Duration::from_secs(15));
    
    let file_sizes = [
        (10240, "10KB"),
        (102400, "100KB"),
        (1048576, "1MB"),
    ];
    
    for (size, label) in file_sizes.iter() {
        let temp_file = NamedTempFile::new().unwrap();
        let data = vec![42u8; *size];
        fs::write(temp_file.path(), &data).unwrap();
        
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::new("roundtrip", label), size, |b, &_size| {
            b.iter(|| {
                let chunks = split_file_into_chunks(temp_file.path(), 8192, "test.bin").unwrap();
                let assembled = assemble_file_from_chunks(&chunks).unwrap();
                verify_file_integrity(&chunks, &assembled).unwrap();
                black_box(assembled)
            })
        });
    }
    group.finish();
}

fn memory_efficiency_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_efficiency");
    
    // Test memory usage patterns with different chunk sizes for large files
    let temp_file = NamedTempFile::new().unwrap();
    let data = vec![42u8; 10485760]; // 10MB file
    fs::write(temp_file.path(), &data).unwrap();
    
    let chunk_sizes = [4096, 65536, 524288]; // 4KB, 64KB, 512KB
    
    for chunk_size in chunk_sizes.iter() {
        group.bench_with_input(BenchmarkId::new("large_file_chunking", chunk_size), chunk_size, |b, &chunk_size| {
            b.iter(|| {
                let chunks = split_file_into_chunks(temp_file.path(), chunk_size, "large.bin").unwrap();
                black_box(chunks)
            })
        });
    }
    
    group.finish();
}

fn chunk_ordering_benchmark(c: &mut Criterion) {
    let temp_file = NamedTempFile::new().unwrap();
    let data = vec![42u8; 102400]; // 100KB
    fs::write(temp_file.path(), &data).unwrap();
    
    let mut chunks = split_file_into_chunks(temp_file.path(), 4096, "test.bin").unwrap();
    
    // Create unordered chunks
    let mut unordered_chunks = chunks.clone();
    unordered_chunks.reverse();
    
    let mut group = c.benchmark_group("chunk_ordering");
    
    group.bench_function("ordered_chunks", |b| {
        b.iter(|| {
            black_box(assemble_file_from_chunks(&chunks).unwrap())
        })
    });
    
    group.bench_function("unordered_chunks", |b| {
        b.iter(|| {
            black_box(assemble_file_from_chunks(&unordered_chunks).unwrap())
        })
    });
    
    group.finish();
}

criterion_group!(
    benches,
    split_file_benchmark,
    chunk_size_comparison_benchmark,
    assemble_file_benchmark,
    verify_chunk_integrity_benchmark,
    verify_file_integrity_benchmark,
    parallel_chunk_processing_benchmark,
    sha256_computation_benchmark,
    chunk_metadata_creation_benchmark,
    roundtrip_benchmark,
    memory_efficiency_benchmark,
    chunk_ordering_benchmark
);
criterion_main!(benches);