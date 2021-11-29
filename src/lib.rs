use sha1::Digest;
use num_bigint::{BigUint};
use num_traits::identities::Zero;
use num_integer::Integer;
use rand::prng::chacha::ChaChaRng;
use rand::{FromEntropy, RngCore};
use Vec;
use num_traits::One;


#[derive(Debug, Clone)]
pub struct EllipticCurveError;

pub struct EllipticCurve {
    pub q: BigUint,
    pub a: BigUint,
    pub b: BigUint,
}

impl EllipticCurve {
    pub fn generate(seed: BigUint, q: BigUint) -> Result<EllipticCurve, EllipticCurveError> {
        let a = EllipticCurve::generate_number(q.bits());
        return EllipticCurve::generate_with_a(seed, q, a);
    }

    pub fn generate_with_a(seed: BigUint, q: BigUint, a: BigUint) -> Result<EllipticCurve, EllipticCurveError> {
        let base2 = BigUint::from(2u8);

        let t = 160;
        let m = q.bits();
        let g = seed.bits() as u32;
        let s = ((m as f64 - 1.0) / t as f64).floor() as u64;
        if s == 0 || t == 0 {
            return Err(EllipticCurveError);
        }
        let k = m - s * t - 1;

        let mut hash = sha1::Sha1::new();
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

            let mut hash = sha1::Sha1::new();
            hash.update(new_seed.to_bytes_be());
            let c_j = hash.finalize();

            let c_j = BigUint::from_bytes_be(&c_j);
            let c_j = c_j * base2.pow((t * (s - j)) as u32);
            c += c_j;
        }

        let exp = BigUint::from(3usize);
        let a3 = a.modpow(&exp, &q);
        let b2 = EllipticCurve::div_n(&a3, &c, &q);

        if 4u8 * a3 + 27u8 * b2.clone() == BigUint::zero() {
            return Err(EllipticCurveError);
        }
        // let b = EllipticCurve::sqrt_n(&b2, &q);
        return Ok(EllipticCurve{ q, a, b: b2});
    }

    fn div_n(a: &BigUint, b: &BigUint, n: &BigUint) -> BigUint { // ToDo: change to Result
        let a = a % n;
        let inv = EllipticCurve::mod_inverse(b, n);
        return (inv * a) % n;
    }

    fn mod_inverse(num: &BigUint, n: &BigUint) -> BigUint { // ToDo: change to Result
        let one = BigUint::one();

        let g = num.gcd(n);
        if g != one {
            return one; // ToDO: return Err
        } else {
            return num.modpow( &(n - 2u8), n);
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
    pub fn generate_with_seed_q(seed: BigUint, q: BigUint) -> Result<ECDomainParameters, EllipticCurveError> {
        let ec = EllipticCurve::generate(seed.clone(), q.clone())?;
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

    #[test]
    fn random_curve_over_192b_prime_field() { // ANSI X9.62 L.6.2.3
        let base2 = BigUint::from(2u8);

        let seed = BigUint::from_str_radix("3045AE6FC8422F64ED579528D38120EAE12196D5", 16).expect("");
        let field = BigUint::from_str_radix("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF", 16).expect("");
        let given_a = BigUint::from_str_radix("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC", 16).expect("");
        let expected_b = BigUint::from_str_radix("64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1", 16).expect("");
        let expected_b2 = expected_b.modpow(&base2, &field);

        let ec = EllipticCurve::generate_with_a(seed, field.clone(), given_a.clone()).expect("No EC returned!");
        assert_eq!(ec.q, field);
        assert_eq!(ec.a, given_a);
        assert_eq!(ec.b, expected_b2);
    }
}
