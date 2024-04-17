use ark_std::test_rng;
use halo2_proofs::arithmetic::Field;
use halo2_proofs::circuit::Layouter;
use halo2_proofs::circuit::SimpleFloorPlanner;
use halo2_proofs::dev::MockProver;
use halo2_proofs::plonk::Circuit;
use halo2_proofs::plonk::ConstraintSystem;
use halo2_proofs::plonk::ErrorFront;
// use halo2curves::grumpkin::Fq;
use halo2curves::bandersnatch::BandersnatchAffine;
use halo2curves::bandersnatch::Fp;
// use halo2curves::bls12_381::Fp;

use crate::arith_gates::ArithOps;
use crate::chip::ECChip;
use crate::config::ECConfig;
use crate::ec_gates::NativeECOps;

#[derive(Default, Debug, Clone, Copy)]
struct ArithTestCircuit {
    f1: Fp,
    f2: Fp,
    f3: Fp,      // f3 = f1 + f2
    f4: Fp,      // f4 = f1 * f2
    f5: [Fp; 6], // partial bit decom
}

impl Circuit<Fp> for ArithTestCircuit {
    type Config = ECConfig<BandersnatchAffine, Fp>;
    type FloorPlanner = SimpleFloorPlanner;

    // #[cfg(feature = "circuit-params")]
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        ECChip::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), ErrorFront> {
        let field_chip = ECChip::construct(config.clone());

        layouter.assign_region(
            || "test field circuit",
            |mut region| {
                let mut offset = 0;

                // unit test: addition
                {
                    let f3_rec =
                        field_chip.add(&mut region, &config, &self.f1, &self.f2, &mut offset)?;
                    let f3 = field_chip.load_private_field(
                        &mut region,
                        &config,
                        &self.f3,
                        &mut offset,
                    )?;
                    region.constrain_equal(f3.cell(), f3_rec.cell())?;
                }

                // unit test: multiplication
                {
                    let f4_rec =
                        field_chip.mul(&mut region, &config, &self.f1, &self.f2, &mut offset)?;
                    let f4 = field_chip.load_private_field(
                        &mut region,
                        &config,
                        &self.f4,
                        &mut offset,
                    )?;
                    region.constrain_equal(f4.cell(), f4_rec.cell())?;
                }

                // unit test: partial bit decompose
                {
                    let _cells = field_chip.partial_bit_decomp(
                        &mut region,
                        &config,
                        self.f5.as_ref(),
                        &mut offset,
                    )?;
                }

                // unit test: decompose u128
                {
                    let bytes = (0..16).map(|x| x).collect::<Vec<u8>>();
                    let a = u128::from_le_bytes(bytes.try_into().unwrap());
                    let _cells =
                        field_chip.decompose_u128(&mut region, &config, &a, &mut offset)?;
                }

                // pad the last two rows
                field_chip.pad(&mut region, &config, &mut offset).unwrap();

                Ok(())
            },
        )?;

        Ok(())
    }
}

#[test]
fn test_field_ops() {
    let k = 10;

    let mut rng = test_rng();

    let f1 = Fp::random(&mut rng);
    let f2 = Fp::random(&mut rng);
    let f3 = f1 + f2;
    let f4 = f1 * f2;
    {
        let f5 = [
            Fp::one(),
            Fp::zero(),
            Fp::zero(),
            Fp::one(),
            f1,
            f1 * Fp::from(16) + Fp::from(9),
        ];
        let circuit = ArithTestCircuit { f1, f2, f3, f4, f5 };

        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }

    // error case: addition fails
    {
        let f3 = f1 + f1;
        let f5 = [
            Fp::one(),
            Fp::zero(),
            Fp::zero(),
            Fp::one(),
            f1,
            f1 * Fp::from(16) + Fp::from(9),
        ];
        let circuit = ArithTestCircuit { f1, f2, f3, f4, f5 };

        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert!(prover.verify().is_err());
    }
    // error case: multiplication fails
    {
        let f4 = f1 * f1;
        let f5 = [
            Fp::one(),
            Fp::zero(),
            Fp::zero(),
            Fp::one(),
            f1,
            f1 * Fp::from(16) + Fp::from(9),
        ];
        let circuit = ArithTestCircuit { f1, f2, f3, f4, f5 };

        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert!(prover.verify().is_err());
    }
    // error case: not binary
    {
        let f5 = [
            Fp::from(2),
            Fp::zero(),
            Fp::zero(),
            Fp::one(),
            f1,
            f1 * Fp::from(16) + Fp::from(10),
        ];
        let circuit = ArithTestCircuit { f1, f2, f3, f4, f5 };

        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert!(prover.verify().is_err());
    }
    // error case: sum not equal
    {
        let f5 = [
            Fp::zero(),
            Fp::zero(),
            Fp::zero(),
            Fp::one(),
            f1,
            f1 * Fp::from(16) + Fp::from(10),
        ];
        let circuit = ArithTestCircuit { f1, f2, f3, f4, f5 };

        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert!(prover.verify().is_err());
    }
}
