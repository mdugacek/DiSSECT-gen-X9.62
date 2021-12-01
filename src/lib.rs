use sha1::Sha1;
use num_bigint::{BigUint};
use num_traits::identities::Zero;
use num_integer::Integer;
use rand::prng::chacha::ChaChaRng;
use rand::{FromEntropy, RngCore};
use Vec;
use digest::Digest;
use num_traits::One;
use sha2::{Sha224, Sha256, Sha384, Sha512};

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

    pub fn generate_224_a(seed: BigUint, q: BigUint, a: BigUint) -> Result<EllipticCurve, EllipticCurveError> {
        EllipticCurve::generate_with_a::<Sha224>(seed, q, a)
    }

    pub fn generate_sha256(seed: BigUint, q: BigUint) -> Result<EllipticCurve, EllipticCurveError> {
        EllipticCurve::generate::<Sha224>(seed, q)
    }

    pub fn generate_sha256_a(seed: BigUint, q: BigUint, a: BigUint) -> Result<EllipticCurve, EllipticCurveError> {
        EllipticCurve::generate_with_a::<Sha256>(seed, q, a)
    }

    pub fn generate_sha384(seed: BigUint, q: BigUint) -> Result<EllipticCurve, EllipticCurveError> {
        EllipticCurve::generate::<Sha384>(seed, q)
    }

    pub fn generate_sha384_a(seed: BigUint, q: BigUint, a: BigUint) -> Result<EllipticCurve, EllipticCurveError> {
        EllipticCurve::generate_with_a::<Sha384>(seed, q, a)
    }

    pub fn generate_sha512(seed: BigUint, q: BigUint) -> Result<EllipticCurve, EllipticCurveError> {
        EllipticCurve::generate::<Sha512>(seed, q)
    }

    pub fn generate_sha512_a(seed: BigUint, q: BigUint, a: BigUint) -> Result<EllipticCurve, EllipticCurveError> {
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
        // let b = EllipticCurve::sqrt_n(&b2, &q);
        return Ok(EllipticCurve{ q, a, b: b2});
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

    fn sqrt_n(num: &BigUint, n: &BigUint) -> BigUint {
        // Takes too long, 22 bit number takes 1s then each bit multiplies time by 2
        let base2 = BigUint::from(2u8);

        let mut ret = BigUint::zero();
        while ret < *n {
            if ret.modpow(&base2, &n) == *num {
                return ret;
            }
            ret += 1u8;
        }
        return BigUint::zero();
    }

    fn generate_number(bit_count: u64) -> BigUint {
        let mut number= Vec::new();
        let mut prng = ChaChaRng::from_entropy();

        let u32_size = 32 as u64;
        let u32_count =  bit_count / u32_size;
        for _ in 0..u32_count {
            number.push(prng.next_u32());
        }

        let mut mask: u32 = 0b0;
        for _ in  0..bit_count % u32_size {
            mask = mask << 1 | 0b1;
        }

        let last_num = prng.next_u32();
        number.push(last_num & mask);

        return BigUint::new(number);
    }
}


pub struct ECDomainParameters {
    seed: BigUint,
    ec: EllipticCurve
}

impl ECDomainParameters {
    pub fn generate_with_seed_q<D: X962HashAlgorithm + Digest>(seed: BigUint, q: BigUint) -> Result<ECDomainParameters, EllipticCurveError> {
        let ec = EllipticCurve::generate::<D>(seed.clone(), q.clone())?;
        // e
        // f
        // g
        // h
        return Ok(ECDomainParameters{seed, ec});
    }

    fn check_if_nearly_prime() {

    }

    fn generate_base_point() {

    }
}


#[cfg(test)]
mod tests {
    use crate::EllipticCurve;
    use crate::BigUint;
    use num_traits::Num;
    use sha1::Sha1;

    fn test_random_curve_over_prime_field(seed: &str, field: &str, a: &str, expected_b: &str) {
        let base2 = BigUint::from(2u8);

        let seed = BigUint::from_str_radix(seed, 16).expect("seed");
        let field = BigUint::from_str_radix(field, 16).expect("field");
        let given_a = BigUint::from_str_radix(a, 16).expect("a");
        let expected_b = BigUint::from_str_radix(expected_b, 16).expect("given b");
        let expected_b2 = expected_b.modpow(&base2, &field);

        let ec = EllipticCurve::generate_with_a::<Sha1>(seed, field.clone(), given_a.clone()).expect("No EC returned!");
        assert_eq!(ec.q, field);
        assert_eq!(ec.a, given_a);
        assert_eq!(ec.b, expected_b2);
    }


    #[test]
    fn random_curve_over_192b_prime_field() { // ANSI X9.62 L.6.2.3
        let seed = "3045AE6FC8422F64ED579528D38120EAE12196D5";
        let field = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF";
        let given_a = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC";
        let expected_b = "64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1";
        test_random_curve_over_prime_field(seed, field, given_a, expected_b);
    }

    #[test]
    fn random_curve_over_224b_prime_field() { // ANSI X9.62 L.6.3.3
        let seed = "BD71344799D5C7FCDC45B59FA3B9AB8F6A948BC5";
        let field = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001";
        let given_a = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE";
        let expected_b = "B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4";
        test_random_curve_over_prime_field(seed, field, given_a, expected_b);
    }

    #[test]
    fn random_curve_over_256b_prime_field() { // ANSI X9.62 L.6.4.3
        let seed = "C49D360886E704936A6678E1139D26B7819F7E90";
        let field = "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF";
        let given_a = "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC";
        let expected_b = "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B";
        test_random_curve_over_prime_field(seed, field, given_a, expected_b);
    }

    #[test]
    fn random_curve_over_384b_prime_field() { // ANSI X9.62 L.6.5.3
        let seed = "A335926AA319A27A1D00896A6773A4827ACDAC73";
        let field = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF";
        let given_a = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC";
        let expected_b = "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF";
        test_random_curve_over_prime_field(seed, field, given_a, expected_b);
    }

    #[test]
    fn random_curve_over_521b_prime_field() { // ANSI X9.62 L.6.6.3
        let seed = "D09E8800291CB85396CC6717393284AAA0DA64BA";
        let field = "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
        let given_a = "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC";
        let expected_b = "0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00";
        test_random_curve_over_prime_field(seed, field, given_a, expected_b);
    }
}
