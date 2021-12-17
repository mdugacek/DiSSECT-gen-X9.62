use std::ffi::{CStr, CString};
use std::os::raw::c_char;

extern "C" {
    fn c_sqrtfp(n_str: *const c_char, p_str: *const c_char, out_str: *mut c_char);
    fn c_points(
        a_str: *const c_char,
        b_str: *const c_char,
        p_str: *const c_char,
        out_str: *mut c_char,
    );
}

pub fn sqrtfp(n: &str, p: &str) -> String {
    let mut buffer: [c_char; 1024] = [0u8; 1024];
    unsafe {
        let n = CString::new(n).unwrap();
        let p = CString::new(p).unwrap();
        c_sqrtfp(n.as_ptr(), p.as_ptr(), buffer.as_mut_ptr());
        CStr::from_ptr(buffer.as_ptr())
            .to_string_lossy()
            .into_owned()
    }
}

pub fn points(a: &str, b: &str, p: &str) -> String {
    let mut buffer: [c_char; 1024] = [0u8; 1024];
    unsafe {
        let a = CString::new(a).unwrap();
        let b = CString::new(b).unwrap();
        let p = CString::new(p).unwrap();
        c_points(a.as_ptr(), b.as_ptr(), p.as_ptr(), buffer.as_mut_ptr());
        CStr::from_ptr(buffer.as_ptr())
            .to_string_lossy()
            .into_owned()
    }
}


use digest::Digest;
use num_bigint::{BigUint, RandBigInt};
use num_integer::Integer;
use num_traits::identities::Zero;
use num_traits::{One, Num};
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512};

extern crate rand;
extern crate num_bigint;
extern crate clap;
use clap::{Arg, App};

pub trait X962SupportedHashAlgorithm {}
impl X962SupportedHashAlgorithm for Sha1 {}
impl X962SupportedHashAlgorithm for Sha224 {}
impl X962SupportedHashAlgorithm for Sha256 {}
impl X962SupportedHashAlgorithm for Sha384 {}
impl X962SupportedHashAlgorithm for Sha512 {}

pub trait X962HashAlgorithm : X962SupportedHashAlgorithm + Digest {}
impl<T: X962SupportedHashAlgorithm + Digest> X962HashAlgorithm for T {}


#[derive(Debug, Clone)]
pub struct EllipticCurveError;

pub struct EllipticCurve {
    pub q: BigUint,
    pub a: BigUint,
    pub b: BigUint,
}

impl EllipticCurve {
    pub fn generate_sha1(seed: BigUint, q: BigUint) -> Result<EllipticCurve, EllipticCurveError> {
        EllipticCurve::generate::<Sha1>(seed, q)
    }

    pub fn generate_sha1_with_a(seed: BigUint, q: BigUint, a: BigUint) -> Result<EllipticCurve, EllipticCurveError> {
        EllipticCurve::generate_with_a::<Sha1>(seed, q, a)
    }

    pub fn generate_sha224(seed: BigUint, q: BigUint) -> Result<EllipticCurve, EllipticCurveError> {
        EllipticCurve::generate::<Sha256>(seed, q)
    }

    pub fn generate_sha224_with_a(seed: BigUint, q: BigUint, a: BigUint) -> Result<EllipticCurve, EllipticCurveError> {
        EllipticCurve::generate_with_a::<Sha224>(seed, q, a)
    }

    pub fn generate_sha256(seed: BigUint, q: BigUint) -> Result<EllipticCurve, EllipticCurveError> {
        EllipticCurve::generate::<Sha224>(seed, q)
    }

    pub fn generate_sha256_with_a(seed: BigUint, q: BigUint, a: BigUint) -> Result<EllipticCurve, EllipticCurveError> {
        EllipticCurve::generate_with_a::<Sha256>(seed, q, a)
    }

    pub fn generate_sha384(seed: BigUint, q: BigUint) -> Result<EllipticCurve, EllipticCurveError> {
        EllipticCurve::generate::<Sha384>(seed, q)
    }

    pub fn generate_sha384_with_a(seed: BigUint, q: BigUint, a: BigUint) -> Result<EllipticCurve, EllipticCurveError> {
        EllipticCurve::generate_with_a::<Sha384>(seed, q, a)
    }

    pub fn generate_sha512(seed: BigUint, q: BigUint) -> Result<EllipticCurve, EllipticCurveError> {
        EllipticCurve::generate::<Sha512>(seed, q)
    }

    pub fn generate_sha512_with_a(seed: BigUint, q: BigUint, a: BigUint) -> Result<EllipticCurve, EllipticCurveError> {
        EllipticCurve::generate_with_a::<Sha512>(seed, q, a)
    }

    pub fn generate<D: X962HashAlgorithm>(seed: BigUint, q: BigUint) -> Result<EllipticCurve, EllipticCurveError> {
        let a = EllipticCurve::generate_number(q.bits());
        return EllipticCurve::generate_with_a::<D>(seed, q, a);
    }

    pub fn generate_with_a<D: X962HashAlgorithm>(seed: BigUint, q: BigUint, a: BigUint) -> Result<EllipticCurve, EllipticCurveError> {
        let base2 = BigUint::from(2u8);

        let t = (D::output_size() * 8) as u64;
        let m = q.bits();
        let g = seed.bits() as u32;
        let s = ((m as f64 - 1.0) / t as f64).floor() as u64;
        if s == 0 || t == 0 {
            return Err(EllipticCurveError);
        }
        let k = m - s * t - 1;

        let mut hash = D::new();
        hash.update(seed.to_bytes_be());
        let h = hash.finalize();
        let h = h.as_slice();

        let mut c = BigUint::from_bytes_be(h);

        c %= base2.pow(k as u32);
        c *= base2.pow((t * s) as u32);

        let mut seed = seed.clone();
        for j in 1..=s {
            seed += 1u8;

            let new_seed = seed.clone();
            let new_seed = new_seed % base2.pow(g);

            let mut hash = D::new();
            hash.update(new_seed.to_bytes_be());
            let c_j = hash.finalize();

            let c_j = BigUint::from_bytes_be(&c_j);
            let c_j = c_j * base2.pow((t * (s - j)) as u32);
            c += c_j;
        }

        let exp = BigUint::from(3usize);
        let a3 = a.modpow(&exp, &q);
        let b2 = EllipticCurve::div_n(&a3, &c, &q)?;

        if 4u8 * a3 + 27u8 * b2.clone() == BigUint::zero() {
            return Err(EllipticCurveError);
        }
        let b = EllipticCurve::sqrt_n(&b2, &q);
        return Ok(EllipticCurve{ q, a, b});
    }

    fn div_n(a: &BigUint, b: &BigUint, n: &BigUint) -> Result<BigUint, EllipticCurveError> {
        let a = a % n;
        let inv = EllipticCurve::mod_inverse(b, n)?;
        return Ok((inv * a) % n);
    }

    fn mod_inverse(num: &BigUint, n: &BigUint) -> Result<BigUint, EllipticCurveError> {
        let one = BigUint::one();

        let g = num.gcd(n);
        if g != one {
            return Err(EllipticCurveError);
        } else {
            return Ok(num.modpow( &(n - 2u8), n));
        }
    }

    fn sqrt_n(num: &BigUint, n: &BigUint) -> BigUint{
        let num_str = num.to_str_radix(10);
        let n_str = n.to_str_radix(10);
        let res = sqrtfp(num_str.as_str(), n_str.as_str());
        return BigUint::from_str_radix(res.as_str(), 10).expect("");
    }

    fn generate_number(bit_count: u64) -> BigUint {
        let mut rng = rand::thread_rng();
        return rng.gen_biguint(bit_count);
    }

    fn order(&self) -> BigUint {
        let q_str = self.q.to_str_radix(10);
        let a_str = self.a.to_str_radix(10);
        let b_str = self.b.to_str_radix(10);
        let ret = points(a_str.as_str(), b_str.as_str(), q_str.as_str());
        return BigUint::from_str_radix(ret.as_str(), 10).expect("");
    }
}


pub struct ECDomainParameters {
    seed: BigUint,
    ec: EllipticCurve
}


impl ECDomainParameters {
    pub fn generate_with_seed_q<D: X962HashAlgorithm + Digest>(seed: BigUint, q: BigUint) -> Result<ECDomainParameters, EllipticCurveError> {
        let ec = EllipticCurve::generate::<D>(seed.clone(), q.clone())?;
        // let u = ec.order();
        // f
        // g
        // h
        return Ok(ECDomainParameters{seed, ec});
    }

    fn check_if_nearly_prime(u: BigUint, l_max: BigUint, r_min: BigUint) -> Result<(BigUint, BigUint), EllipticCurveError>{
        let mut n = u;
        let mut h = BigUint::one();
        let mut l = BigUint::from(2u8);
        while l != l_max {
            let l_bu = l.clone(); // ToDo: fix
            while l_bu.clone() % n.clone() == BigUint::zero() {
                n = n / &l;
                h = h * &l;
                if n < r_min {
                    return Err(EllipticCurveError);
                }
            }
            l += 1u8;
        }

        if ECDomainParameters::probabilistic_primality_test(n.clone()) {
            return Ok((h, n));
        }
        return Err(EllipticCurveError);
    }

    fn probabilistic_primality_test(n: BigUint) -> bool {
        let two = BigUint::from(2u8);

        let v = BigUint::zero();
        let w = BigUint::zero();
        let t = BigUint::from(50usize);
        // ToDo: implement point a) on page 11, algorithm A.1.1

        let j = BigUint::one();
        while j != t {
            let mut rng = rand::thread_rng();
            let a = rng.gen_biguint_range(&BigUint::from(2usize), &(&n - 1usize));
            let b = a.modpow(&w, &n);
            if b == BigUint::one() || b == (&n - 1usize) {
                continue;
            }

            let i = BigUint::one();
            let mut fail = true;
            while i != (&v - 1usize) {
                let b = b.modpow(&two, &n);
                if b == &n - 1usize {
                    fail = false;
                    break;
                }
                if b == BigUint::one() {
                    return false;
                }
            }
            if fail {
                return false;
            }
        }
        return true;
    }
}


#[cfg(test)]
mod tests {
    use crate::BigUint;
    use crate::EllipticCurve;
    use num_traits::Num;
    use sha1::Sha1;

    fn test_random_curve_over_prime_field(seed: &str, field: &str, a: &str, expected_b: &str) {
        let base2 = BigUint::from(2u8);

        let seed = BigUint::from_str_radix(seed, 16).expect("seed");
        let field = BigUint::from_str_radix(field, 16).expect("field");
        let given_a = BigUint::from_str_radix(a, 16).expect("a");
        let expected_b = BigUint::from_str_radix(expected_b, 16).expect("given b");

        let ec = EllipticCurve::generate_with_a::<Sha1>(seed, field.clone(), given_a.clone())
            .expect("No EC returned!");
        let second_b = &field - &ec.b;

        assert_eq!(ec.q, field);
        assert_eq!(ec.a, given_a);
        assert!(second_b == expected_b || ec.b == expected_b);
    }

    #[test]
    fn random_curve_over_192b_prime_field() {
        // ANSI X9.62 L.6.2.3
        let seed = "3045AE6FC8422F64ED579528D38120EAE12196D5";
        let field = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF";
        let given_a = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC";
        let expected_b = "64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1";
        test_random_curve_over_prime_field(seed, field, given_a, expected_b);
    }

    #[test]
    fn random_curve_over_224b_prime_field() {
        // ANSI X9.62 L.6.3.3
        let seed = "BD71344799D5C7FCDC45B59FA3B9AB8F6A948BC5";
        let field = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001";
        let given_a = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE";
        let expected_b = "B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4";
        test_random_curve_over_prime_field(seed, field, given_a, expected_b);
    }

    #[test]
    fn random_curve_over_256b_prime_field() {
        // ANSI X9.62 L.6.4.3
        let seed = "C49D360886E704936A6678E1139D26B7819F7E90";
        let field = "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF";
        let given_a = "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC";
        let expected_b = "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B";
        test_random_curve_over_prime_field(seed, field, given_a, expected_b);
    }

    #[test]
    fn random_curve_over_384b_prime_field() {
        // ANSI X9.62 L.6.5.3
        let seed = "A335926AA319A27A1D00896A6773A4827ACDAC73";
        let field = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF";
        let given_a = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC";
        let expected_b = "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF";
        test_random_curve_over_prime_field(seed, field, given_a, expected_b);
    }

    #[test]
    fn random_curve_over_521b_prime_field() {
        // ANSI X9.62 L.6.6.3
        let seed = "D09E8800291CB85396CC6717393284AAA0DA64BA";
        let field = "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
        let given_a = "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC";
        let expected_b = "0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00";
        test_random_curve_over_prime_field(seed, field, given_a, expected_b);
    }
}

fn generate_ec(seed: &str, q: &str, hash_algorithm: &str, a: Option<&str>) -> Result<EllipticCurve, EllipticCurveError> {
    let seed = BigUint::from_str_radix(seed, 16).expect("incorrect format of given seed");
    let q = BigUint::from_str_radix(q, 16).expect("incorrect format of given q");

    if a.is_some() {
        let a = BigUint::from_str_radix(a.unwrap(), 16).expect("incorrect format of given a");
        println!("a: {}", a);
        match hash_algorithm {
            "sha1" => EllipticCurve::generate_sha1_with_a(seed, q, a),
            "sha224" => EllipticCurve::generate_sha224_with_a(seed, q, a),
            "sha256" => EllipticCurve::generate_sha256_with_a(seed, q, a),
            "sha384" => EllipticCurve::generate_sha384_with_a(seed, q, a),
            "sha512" => EllipticCurve::generate_sha512_with_a(seed, q, a),
            _ => Err(EllipticCurveError)
        }
    } else {
        match hash_algorithm {
            "sha1" => EllipticCurve::generate_sha1(seed, q),
            "sha224" => EllipticCurve::generate_sha224(seed, q),
            "sha256" => EllipticCurve::generate_sha256(seed, q),
            "sha384" => EllipticCurve::generate_sha384(seed, q),
            "sha512" => EllipticCurve::generate_sha512(seed, q),
            _ => Err(EllipticCurveError)
        }
    }
}

fn main() {
    let matches = App::new("DiSSECT-gen-X9.62")
        .arg(Arg::with_name("seed").short("-s").long("--seed").value_name("SEED").help("seed given as string of hexadecimal values").required(true).takes_value(true))
        .arg(Arg::with_name("field size").short("-q").long("--field-size").value_name("FIELD_SIZE").help("field size given as string of hexadecimal values").required(true).takes_value(true))
        .arg(Arg::with_name("hash algorithm").long("--hash-algorithm").default_value("sha1").takes_value(true))
        .arg(Arg::with_name("provided a").short("-a").long("--with-a").help("a parameter of generated ec given as string of hexadecimal values").takes_value(true))
        .get_matches();

    let seed = matches.value_of("seed").expect("");
    println!("seed: {}", seed);
    let field_size = matches.value_of("field size").expect("");
    println!("field_size: {}", field_size);

    let hash_algorithm = matches.value_of("hash algorithm").expect("");
    let a = matches.value_of("provided a");

    let ec = generate_ec(seed, field_size, hash_algorithm, a);
    if ec.is_err() {
        println!("EC generation resulted in error.");
    } else {
        let ec = ec.unwrap();
        println!("EC generated successfully:");
        println!("a: {}", ec.a);
        println!("b: {}", ec.b);
        println!("order: {}", ec.order());
    }
}