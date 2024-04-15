use std::ops::Mul;

use ark_std::test_rng;
use halo2_proofs::arithmetic::Field;
use halo2_proofs::circuit::Layouter;
use halo2_proofs::circuit::SimpleFloorPlanner;
use halo2_proofs::dev::MockProver;
use halo2_proofs::halo2curves::group::Curve;
use halo2_proofs::halo2curves::group::Group;
use halo2_proofs::plonk::Circuit;
use halo2_proofs::plonk::ConstraintSystem;
use halo2_proofs::plonk::ErrorFront;
// use halo2curves::grumpkin::Fq;
// use halo2curves::grumpkin::Fr;
// use halo2curves::grumpkin::G1Affine;
// use halo2curves::grumpkin::G1;

use halo2curves::bandersnatch;
use halo2curves::bandersnatch::Fp as Fq;
use halo2curves::bandersnatch::Fr;
use halo2curves::bandersnatch::BandersnatchTEAffine as G1Affine;
use halo2curves::bandersnatch::BandersnatchTE as G1;
use halo2curves::ff::PrimeField;


use crate::chip::ECChip;
use crate::config::ECConfig;
use crate::ec_gates::NativeECOps;
use crate::ArithOps;

#[derive(Default, Debug, Clone, Copy)]
struct ECTestCircuit {
    s: Fr,
    p1: G1Affine,
    p2: G1Affine,
    p3: G1Affine, // p1 + p2
    p4: G1Affine, // 2p1
    p5: G1Affine, // p1 * s
}

impl Circuit<Fq> for ECTestCircuit {
    type Config = ECConfig<G1Affine, Fq>;
    type FloorPlanner = SimpleFloorPlanner;

    // #[cfg(feature = "circuit-params")]
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fq>) -> Self::Config {
        ECChip::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fq>,
    ) -> Result<(), ErrorFront> {
        let ec_chip = ECChip::construct(config.clone());

        layouter.assign_region(
            || "test ec circuit",
            |mut region| {
                let mut offset = 0;
                // unit test: `load private unchecked`, then `enforce is on curve`
                let _p1 = {
                    let p1 = ec_chip.load_private_point_unchecked(
                        &mut region,
                        &config,
                        &self.p1,
                        &mut offset,
                    ).unwrap();
                    ec_chip.enforce_on_curve(&mut region, &config, &p1, &mut offset).unwrap();
                    p1
                };
                // unit test: load private
                let _p2 =
                    ec_chip.load_private_point(&mut region, &config, &self.p2, &mut offset).unwrap();
                let p3 = ec_chip.load_private_point(&mut region, &config, &self.p3, &mut offset).unwrap();
                let p4 = ec_chip.load_private_point(&mut region, &config, &self.p4, &mut offset).unwrap();
                let p5 = ec_chip.load_private_point(&mut region, &config, &self.p5, &mut offset).unwrap();

                // unit test: point addition with 1
                {
                    let p1 = ec_chip.load_private_point_unchecked(
                        &mut region,
                        &config,
                        &self.p1,
                        &mut offset,
                    ).unwrap();
                    let p2 = ec_chip.load_private_point_unchecked(
                        &mut region,
                        &config,
                        &self.p2,
                        &mut offset,
                    ).unwrap();
                    let bit = ec_chip.load_private_field(
                        &mut region,
                        &config,
                        &Fq::from(1),
                        &mut offset,
                    )?;
                    let p3_rec = ec_chip.conditional_point_add(
                        &mut region,
                        &config,
                        &p1,
                        &p2,
                        &bit,
                        &mut offset,
                    ).unwrap();

                    region.constrain_equal(p3.x.cell(), p3_rec.x.cell())?;
                    region.constrain_equal(p3.y.cell(), p3_rec.y.cell())?;
                    println!("here we are");
                }

                // unit test: point addition with 0
                {
                    let p1 = ec_chip.load_private_point_unchecked(
                        &mut region,
                        &config,
                        &self.p1,
                        &mut offset,
                    ).unwrap();
                    let p2 = ec_chip.load_private_point_unchecked(
                        &mut region,
                        &config,
                        &self.p2,
                        &mut offset,
                    ).unwrap();
                    let bit = ec_chip.load_private_field(
                        &mut region,
                        &config,
                        &Fq::from(0),
                        &mut offset,
                    ).unwrap();
                    let p3_rec = ec_chip.conditional_point_add(
                        &mut region,
                        &config,
                        &p1,
                        &p2,
                        &bit,
                        &mut offset,
                    ).unwrap();

                    region.constrain_equal(p1.x.cell(), p3_rec.x.cell())?;
                    region.constrain_equal(p1.y.cell(), p3_rec.y.cell())?;
                }

                // unit test: point doubling
                {
                    let p1 = ec_chip.load_private_point_unchecked(
                        &mut region,
                        &config,
                        &self.p1,
                        &mut offset,
                    ).unwrap();
                    let p4_rec = ec_chip.point_double(&mut region, &config, &p1, &mut offset).unwrap();

                    region.constrain_equal(p4.x.cell(), p4_rec.x.cell())?;
                    region.constrain_equal(p4.y.cell(), p4_rec.y.cell())?;
                }

                // unit test: scalar decomposition
                {
                    let start = offset;
                    let _scalar_cells =
                        ec_chip.decompose_scalar(&mut region, &config, &self.s, &mut offset).unwrap();
                    println!("scalar decompose uses {} rows", offset - start);
                }

                // // unit test: curve mul
                {
                    let start = offset;
                    let p5_rec =
                        ec_chip.point_mul(&mut region, &config, &self.p1, &self.s, &mut offset).unwrap();
                    region.constrain_equal(p5.x.cell(), p5_rec.x.cell())?;
                    region.constrain_equal(p5.y.cell(), p5_rec.y.cell())?;

                    println!("p5.x.cell() is: {:?}", p5.x.value());
                    println!("p5_rec.x.cell() is: {:?}", p5_rec.x.value());

                    println!("p5.y.cell() is: {:?}", p5.y.value());
                    println!("p5_rec.y.cell() is: {:?}", p5_rec.y.value());


                    println!("curve mul uses {} rows", offset - start);
                    println!("offset here is: {}", offset);
                }

                // pad the last two rows
                ec_chip.pad(&mut region, &config, &mut offset).unwrap();

                Ok(())
            },
        )?;

        Ok(())
    }
}
// 
// x: AssignedCell { value: Value { inner: Some(0x2a7a99b0870a6244304b9231050859771fe941cad1bcaede655d2278621a3466) },
//  cell: Cell { region_index: RegionIndex(0), row_offset: 0, column: Column { index: 0, column_type: Advice } },
//  _marker: PhantomData<bls12_381::scalar::Scalar> },
// y: AssignedCell { value: Value { inner: Some(0x2663e58bc157a7cf84d49524700a147bb53489232ea5962c3765bbfe95004080) },
//  cell: Cell { region_index: RegionIndex(0), row_offset: 0, column: Column { index: 1, column_type: Advice } },
//  _marker: PhantomData<bls12_381::scalar::Scalar> } 
// 41515536288062376014772236515869989659801672835942349428353392091902613913603
#[test]
fn test_ec_ops() {
    let k = 14;

    // note: we are not using random values as random() doesn't work for generating random bandersnatch points
    let mut rng = test_rng();
    let sa = Fr::from(55);

    let p1 = (G1::generator()* Fr::from(123123)).to_affine();
    let p2_mid = G1::generator() * sa;
    let p2 = p2_mid.to_affine();
    let p3 = (p1 + p2).to_affine();
    let p4 = (p1 + p1).to_affine(); 
    let p5 = p1.mul(sa.clone()).to_affine();

    {
        let circuit = ECTestCircuit {
            s: sa,
            p1,
            p2,
            p3,
            p4,
            p5,
        };

        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }

    // error case: add not equal
    {
        let p3 = (p1 + p1).to_affine();
        let circuit = ECTestCircuit {
            s: sa,
            p1,
            p2,
            p3,
            p4,
            p5,
        };

        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert!(prover.verify().is_err());
    }

    // error case: double not equal
    {
        let p4 = (p1 + p2).to_affine();
        let circuit = ECTestCircuit {
            s: sa,
            p1,
            p2,
            p3,
            p4,
            p5,
        };

        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert!(prover.verify().is_err());
    }
}
