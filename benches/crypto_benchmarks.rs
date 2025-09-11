use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use n0n::crypto::*;
use n0n::utils::{compute_sha256, encode_base64, decode_base64};
use std::time::Duration;

fn keypair_generation_benchmark(c: &mut Criterion) {
    init();
    
    c.bench_function("keypair_generation", |b| {
        b.iter(|| {
            black_box(generate_keypair())
        })
    });
}

fn encryption_benchmark(c: &mut Criterion) {
    init();
    let (recipient_pk, _recipient_sk) = generate_keypair();
    let (_sender_pk, sender_sk) = generate_keypair();
    
    let mut group = c.benchmark_group("encryption");
    
    for size in [1024, 4096, 16384, 65536, 262144].iter() {
        let data = vec![42u8; *size];
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::new("encrypt_chunk", size), size, |b, &size| {
            let data = vec![42u8; size];
            b.iter(|| {
                black_box(encrypt_chunk(&data, &recipient_pk, &sender_sk).unwrap())
            })
        });
    }
    group.finish();
}

fn decryption_benchmark(c: &mut Criterion) {
    init();
    let (recipient_pk, recipient_sk) = generate_keypair();
    let (sender_pk, sender_sk) = generate_keypair();
    
    let mut group = c.benchmark_group("decryption");
    
    for size in [1024, 4096, 16384, 65536, 262144].iter() {
        let data = vec![42u8; *size];
        let (ciphertext, nonce_b64) = encrypt_chunk(&data, &recipient_pk, &sender_sk).unwrap();
        
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::new("decrypt_chunk", size), size, |b, &_size| {
            b.iter(|| {
                black_box(decrypt_chunk(&ciphertext, &nonce_b64, &sender_pk, &recipient_sk).unwrap())
            })
        });
    }
    group.finish();
}

fn precompute_benchmark(c: &mut Criterion) {
    init();
    let (recipient_pk, _recipient_sk) = generate_keypair();
    let (_sender_pk, sender_sk) = generate_keypair();
    
    c.bench_function("precompute_shared", |b| {
        b.iter(|| {
            black_box(precompute_shared(&sender_sk, &recipient_pk))
        })
    });
}

fn encrypt_with_nonce_benchmark(c: &mut Criterion) {
    init();
    let (recipient_pk, _recipient_sk) = generate_keypair();
    let (_sender_pk, sender_sk) = generate_keypair();
    let nonce_bytes = vec![1u8; NONCEBYTES];
    
    let mut group = c.benchmark_group("encrypt_with_nonce");
    
    for size in [1024, 4096, 16384, 65536].iter() {
        let data = vec![42u8; *size];
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::new("encrypt_with_nonce", size), size, |b, &size| {
            let data = vec![42u8; size];
            b.iter(|| {
                black_box(encrypt_with_nonce(&data, &nonce_bytes, &recipient_pk, &sender_sk).unwrap())
            })
        });
    }
    group.finish();
}

fn hash_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("hashing");
    
    for size in [1024, 4096, 16384, 65536, 262144, 1048576].iter() {
        let data = vec![42u8; *size];
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::new("sha256", size), size, |b, &_size| {
            b.iter(|| {
                black_box(compute_sha256(&data))
            })
        });
    }
    group.finish();
}

fn base64_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("base64");
    
    for size in [1024, 4096, 16384, 65536, 262144].iter() {
        let data = vec![42u8; *size];
        let encoded = encode_base64(&data);
        
        group.throughput(Throughput::Bytes(*size as u64));
        
        group.bench_with_input(BenchmarkId::new("encode", size), size, |b, &_size| {
            b.iter(|| {
                black_box(encode_base64(&data))
            })
        });
        
        group.bench_with_input(BenchmarkId::new("decode", size), size, |b, &_size| {
            b.iter(|| {
                black_box(decode_base64(&encoded).unwrap())
            })
        });
    }
    group.finish();
}

fn end_to_end_crypto_benchmark(c: &mut Criterion) {
    init();
    let (recipient_pk, recipient_sk) = generate_keypair();
    let (sender_pk, sender_sk) = generate_keypair();
    
    let mut group = c.benchmark_group("end_to_end_crypto");
    group.measurement_time(Duration::from_secs(10));
    
    for size in [1024, 16384, 65536].iter() {
        let data = vec![42u8; *size];
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::new("encrypt_decrypt_roundtrip", size), size, |b, &_size| {
            b.iter(|| {
                let (ciphertext, nonce_b64) = encrypt_chunk(&data, &recipient_pk, &sender_sk).unwrap();
                let decrypted = decrypt_chunk(&ciphertext, &nonce_b64, &sender_pk, &recipient_sk).unwrap();
                black_box(decrypted)
            })
        });
    }
    group.finish();
}

fn batch_encryption_benchmark(c: &mut Criterion) {
    init();
    let (recipient_pk, _recipient_sk) = generate_keypair();
    let (_sender_pk, sender_sk) = generate_keypair();
    
    let mut group = c.benchmark_group("batch_encryption");
    group.measurement_time(Duration::from_secs(15));
    
    // Simulate encrypting multiple small chunks vs fewer large chunks
    let small_chunks: Vec<Vec<u8>> = (0..100).map(|_| vec![42u8; 1024]).collect(); // 100 x 1KB
    let large_chunks: Vec<Vec<u8>> = (0..10).map(|_| vec![42u8; 10240]).collect(); // 10 x 10KB
    
    group.bench_function("100_small_chunks", |b| {
        b.iter(|| {
            for chunk in &small_chunks {
                black_box(encrypt_chunk(chunk, &recipient_pk, &sender_sk).unwrap());
            }
        })
    });
    
    group.bench_function("10_large_chunks", |b| {
        b.iter(|| {
            for chunk in &large_chunks {
                black_box(encrypt_chunk(chunk, &recipient_pk, &sender_sk).unwrap());
            }
        })
    });
    
    group.finish();
}

fn memory_usage_benchmark(c: &mut Criterion) {
    init();
    let (recipient_pk, recipient_sk) = generate_keypair();
    let (sender_pk, sender_sk) = generate_keypair();
    
    // Test memory efficiency with large data
    let large_data = vec![42u8; 1048576]; // 1MB
    let (ciphertext, nonce_b64) = encrypt_chunk(&large_data, &recipient_pk, &sender_sk).unwrap();
    
    c.bench_function("memory_large_decrypt", |b| {
        b.iter(|| {
            black_box(decrypt_chunk(&ciphertext, &nonce_b64, &sender_pk, &recipient_sk).unwrap())
        })
    });
}

criterion_group!(
    benches,
    keypair_generation_benchmark,
    encryption_benchmark,
    decryption_benchmark,
    precompute_benchmark,
    encrypt_with_nonce_benchmark,
    hash_benchmark,
    base64_benchmark,
    end_to_end_crypto_benchmark,
    batch_encryption_benchmark,
    memory_usage_benchmark
);
criterion_main!(benches);