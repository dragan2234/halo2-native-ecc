use std::u128;

use halo2_frontend::circuit::Value;
use halo2curves::ff::PrimeField;
use halo2curves::CurveAffine;

pub(crate) fn leak<T: Copy + Default>(a: &Value<&T>) -> T {
    let mut t = T::default();
    a.map(|x| t = *x);
    t
}

/// Split a scalar field elements into high and low and
/// store the high and low in base field.
pub(crate) fn field_decompose_u128<S>(e: &S) -> (u128, u128)
where
    S: PrimeField<Repr = [u8; 32]>,
{
    let repr = e.to_repr();
    let high = u128::from_le_bytes(repr[16..].try_into().unwrap());
    let low = u128::from_le_bytes(repr[..16].try_into().unwrap());
    (high, low)
}

/// Split a scalar field elements into high and low and
/// store the high and low in base field.
#[allow(dead_code)]
pub(crate) fn field_decompose<F, S>(e: &S) -> (F, F)
where
    F: PrimeField,
    S: PrimeField<Repr = [u8; 32]>,
{
    let repr = e.to_repr();
    let high = F::from_u128(u128::from_le_bytes(repr[16..].try_into().unwrap()));
    let low = F::from_u128(u128::from_le_bytes(repr[..16].try_into().unwrap()));
    (high, low)
}

#[allow(dead_code)]
pub(crate) fn to_le_bits<F: PrimeField<Repr = [u8; 32]>>(e: &F) -> Vec<bool> {
    let mut res = vec![];
    let repr = e.to_repr();
    for e in repr.iter() {
        res.extend_from_slice(byte_to_le_bits(e).as_slice())
    }
    res
}

#[inline]
fn byte_to_le_bits(b: &u8) -> Vec<bool> {
    let mut t = *b;
    let mut res = vec![];
    for _ in 0..8 {
        res.push(t & 1 == 1);
        t >>= 1;
    }
    res
}

#[inline]
pub(crate) fn decompose_u128(a: &u128) -> Vec<u64> {
    a.to_le_bytes()
        .iter()
        .flat_map(|x| {
            byte_to_le_bits(x)
                .iter()
                .map(|&x| x as u64)
                .collect::<Vec<_>>()
        })
        .collect()
}

#[inline]
// hardcoded value for `-2^256 * generator` for Grumpkin curve
pub(crate) fn neg_generator_times_2_to_256<C, F>() -> (C, F, F)
where
    F: PrimeField<Repr = [u8; 32]>,
    C: CurveAffine<Base = F>,
{
    let x = F::from_str_vartime(
        "18743181854947712744276314946015096264026721778860333623839716915275138628836",
    )
    .unwrap();
    let y = F::from_str_vartime(
        "43352142484310984921680343085101029755736011421988478594111694112306153004843",
    )
    .unwrap();
    (C::from_xy(x, y).unwrap(), x, y)
}

#[cfg(test)]
mod test {
    use halo2_proofs::arithmetic::Field;
    use halo2curves::bandersnatch;
    // use halo2curves::grumpkin::Fq;
    // use halo2curves::grumpkin::Fr;
    use halo2curves::bandersnatch::Fp;
    use halo2curves::bandersnatch::Fr;
    use halo2curves::group::Curve;

    use crate::util::byte_to_le_bits;
    use crate::util::to_le_bits;

    use super::decompose_u128;
    use super::field_decompose;

    #[test]
    fn test_neg_generator_times_2_to_256() {
        // 5BC8F5F97CD877D899AD88181CE5880FFB38EC08FFFB13FCFFFFFFFD00000003
        // let neg_2_to_256 = Fq::from([
        //     0xFFFFFFFD00000003,
        //     0xFB38EC08FFFB13FC,
        //     0x99AD88181CE5880F,
        //     0x5BC8F5F97CD877D8
        // ]);

        let neg_2_to_256 = Fr::from_raw([
                        0xFFFFFFFD00000003,
            0xFB38EC08FFFB13FC,
            0x99AD88181CE5880F,
            0x5BC8F5F97CD877D8
        ]);

        let g_times_neg_2_to_256 = bandersnatch::BandersnatchTE::generator() * neg_2_to_256;
        
        let gqew = g_times_neg_2_to_256.to_affine().x;

        println!("g_times_neg_2_to_256: x: {:?}", g_times_neg_2_to_256.to_affine().x);
        println!("g_times_neg_2_to_256: y: {:?}", g_times_neg_2_to_256.to_affine().y);


    }

    #[test]
    fn test_to_bites() {
        assert_eq!(
            byte_to_le_bits(&4),
            vec![false, false, true, false, false, false, false, false]
        );

        {
            let f = Fr::from(4);
            let sequence = to_le_bits(&f);

            for (i, v) in sequence.iter().enumerate() {
                if i == 2 {
                    assert_eq!(*v, true)
                } else {
                    assert_eq!(*v, false)
                }
            }
        }

        {
            let f = Fr::from(4 + (1 << 13));
            let sequence = to_le_bits(&f);

            for (i, v) in sequence.iter().enumerate() {
                if i == 2 || i == 13 {
                    assert_eq!(*v, true, "{}-th coefficient failed", i)
                } else {
                    assert_eq!(*v, false, "{}-th coefficient failed", i)
                }
            }
        }
    }

    #[test]
    fn test_field_decom() {
        let mut rng = ark_std::test_rng();
        let a = Fr::random(&mut rng);
        let (_high, _low) = field_decompose::<Fp, Fr>(&a);

        // println!("{:?}", a);
        // println!("{:?}", high);
        // println!("{:?}", low);

        let a = u128::from_le_bytes([1; 16]);
        let _bits = decompose_u128(&a);
        // println!("{0:x?}", a);
        // println!("{:?}", bits);
        // panic!()
    }
}
