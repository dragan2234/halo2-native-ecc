use std::default;
use std::marker::PhantomData;

use halo2_proofs::arithmetic::Field;
use halo2_proofs::halo2curves::ff::PrimeField;
use halo2_proofs::halo2curves::pluto_eris::FpRepr;
use halo2_proofs::halo2curves::CurveAffine;
use halo2_proofs::plonk::Advice;
use halo2_proofs::plonk::Column;
use halo2_proofs::plonk::Expression;
use halo2_proofs::plonk::Selector;
use halo2_proofs::poly::Rotation;
use halo2_frontend::plonk::VirtualCells;
use halo2curves::bandersnatch;
use halo2curves::bandersnatch::Bandersnatch;
use halo2curves::bandersnatch::BandersnatchTEAffine;
use halo2curves::bandersnatch::TwistedEdwardsCurveAffineExt;
use halo2curves::bandersnatch::Fr as Scalar;
use halo2curves::bandersnatch::TwistedEdwardsCurveExt;
use crate::config::bandersnatch::Fp;

/// Three advices and two additions
#[derive(Clone, Debug)]
pub struct ECConfig<C, F>
where
    // the embedded curve, i.e., Grumpkin
    C: CurveAffine<Base = F>,
    // the field for circuit, i.e., BN::Scalar
    F: Field,
{
    // witnesses
    pub(crate) a: Column<Advice>,
    pub(crate) b: Column<Advice>,

    // selectors
    pub(crate) q_ec_enable: Selector, // ec is enabled
    pub(crate) q1: Selector,          // ec conditional add
    pub(crate) q2: Selector,          // ec double
    pub(crate) q3: Selector,          // ec on curve

    pub(crate) _phantom: PhantomData<C>,
}

impl<C, F> ECConfig<C, F>
where
    C: CurveAffine<Base = F>,
    F: PrimeField<Repr = [u8; 32]>,
{
    pub(crate) fn conditional_ec_add_gate(&self, meta: &mut VirtualCells<F>) -> Expression<F> {
        let one = Expression::Constant(F::ONE);

        let constant_a = F::from(5).neg();
        let constant_d = F::from_repr(halo2curves::bandersnatch::BandersnatchTE::d().to_repr()).unwrap();

        // let constant_d: F = halo2curves::bandersnatch::BandersnatchTE::d().try_into();
        let curve_param_a_expr = Expression::Constant(constant_a);
        let curve_param_d_expr = Expression::Constant(constant_d);


        let a0 = meta.query_advice(self.a, Rotation::cur());
        let b0 = meta.query_advice(self.b, Rotation::cur());
        let a1 = meta.query_advice(self.a, Rotation::next());
        let b1 = meta.query_advice(self.b, Rotation::next());
        let condition = meta.query_advice(self.a, Rotation(2));
        let a2 = meta.query_advice(self.a, Rotation(3));
        let b2 = meta.query_advice(self.b, Rotation(3));


        let divider_1 = one.clone() + curve_param_d_expr.clone() * a0.clone() * a1.clone() * b0.clone() * b1.clone();

        let divider_2 = one.clone() - curve_param_d_expr.clone() * a0.clone() * a1.clone() * b0.clone() * b1.clone();

        let dividend_1 = a0.clone() * b1.clone() + b0.clone() * a1.clone();

        let dividend_2 = b0.clone() * b1.clone() - curve_param_a_expr.clone() * a0.clone() * a1.clone();


        let x3_comp = a2.clone() * divider_1 - dividend_1;

        let y3_comp = b2.clone() * divider_2 - dividend_2;


        // | a  | b  |
        // -----------
        // | x1 | y1 |
        // | x2 | y2 |
        // | c  |    |
        // | x3 | y3 |
        // Given (x1, y1), (x2, y2)
        // if condition is true, we return (x1, y1) + (x2, y2)
        // else we return (x1, y1)
        // x3 = (x1*y2+y1*x2)/(1+d*x1*x2*y1*y2) -> (x1*y2+y1*x2)/(1+d*x1*x2*y1*y2) - x3 == 0
        // y3 = (y1*y2-a*x1*x2)/(1-d*x1*x2*y1*y2) -> (y1*y2-a*x1*x2)/(1-d*x1*x2*y1*y2) - y3 == 0

        condition.clone() * x3_comp.clone() 
        + condition.clone() * y3_comp.clone()
        + (one.clone() - condition.clone()) * (a2.clone() - a0)
        + (one - condition) * (b2.clone() - b0)
        // TODO: enforce the result is on curve
        // + a2.clone() * a2.clone() * a2
        // - b2.clone() * b2
        // + curve_param_b_expr
    }

    /// (x1, y1) and (x3, -y3) are on a tangential line of the curve
    pub(crate) fn ec_double_gate(&self, meta: &mut VirtualCells<F>) -> Expression<F> {
        let one = Expression::Constant(F::ONE);


        let constant_a = F::from(5).neg();
        let constant_d = F::from_repr(halo2curves::bandersnatch::BandersnatchTE::d().to_repr()).unwrap();


        let curve_param_a_expr = Expression::Constant(constant_a);
        let curve_param_d_expr = Expression::Constant(constant_d);

        let a0 = meta.query_advice(self.a, Rotation::cur());
        let b0 = meta.query_advice(self.b, Rotation::cur());
        let a1 = meta.query_advice(self.a, Rotation::next());
        let b1 = meta.query_advice(self.b, Rotation::next());

        /*
            (x1*y1+y1*x1) - x3 * (1+d*x1*x1*y1*y1) == 0
            (y1*y1-a*x1*x1) - y3 * (1-d*x1*x1*y1*y1) == 0
         */
        // | a  | b  |
        // -----------
        // | x1 | y1 |
        // | x3 | y3 |

        let x3_equation = a0.clone()*b0.clone() + b0.clone()*a0.clone() - a1.clone() * (one.clone() + curve_param_d_expr.clone() * a0.clone().square()*b0.clone().square());
        let y3_equation = (b0.clone().square() - curve_param_a_expr.clone() * a0.clone().square()) - b1.clone() * (one.clone() - curve_param_d_expr.clone() * a0.clone().square()*b0.clone().square());

        x3_equation + y3_equation
        // TODO: enforce the result is on curve
        // + a1.clone() * a1.clone() * a1
        //     - b1.clone() * b1
        //     + curve_param_b_expr
        // + one.clone()-one.clone()
    }

    /// (x1, y1) is on curve
    /// TODO: change for bandersnatch
    pub(crate) fn on_curve_gate(&self, meta: &mut VirtualCells<F>) -> Expression<F> {

        let one = Expression::Constant(F::from(1));

        let constant_a = F::from(5).neg();
        let constant_d = F::from_repr(halo2curves::bandersnatch::BandersnatchTE::d().to_repr()).unwrap();

        let curve_param_a_expr = Expression::Constant(constant_a);
        let curve_param_d_expr = Expression::Constant(constant_d);

        let a0 = meta.query_advice(self.a, Rotation::cur()); // x
        let b0 = meta.query_advice(self.b, Rotation::cur()); // y


        // −5x^2+y^2 = 1+dx^2*y^2
        curve_param_a_expr * a0.clone().square() + b0.clone().square() - one - curve_param_d_expr * a0.clone().square() * b0.clone().square()
    }

    /// partial bit decom
    /// - y3 = x1 + 2y1 + 4x2 + 8y2 + 16x3
    /// - x1, y1, x2, y2 are all binary
    pub(crate) fn partial_bit_decom_gate(&self, meta: &mut VirtualCells<F>) -> Expression<F> {
        let one = Expression::Constant(F::ONE);
        let two = Expression::Constant(F::from(2));
        let four = Expression::Constant(F::from(4));
        let eight = Expression::Constant(F::from(8));
        let sixteen = Expression::Constant(F::from(16));

        let a0 = meta.query_advice(self.a, Rotation::cur());
        let b0 = meta.query_advice(self.b, Rotation::cur());
        let a1 = meta.query_advice(self.a, Rotation::next());
        let b1 = meta.query_advice(self.b, Rotation::next());
        let a2 = meta.query_advice(self.a, Rotation(2));
        let b2 = meta.query_advice(self.b, Rotation(2));

        // y3 = x1 + 2y1 + 4x2 + 8y2 + 16x3
        a0.clone() + two * b0.clone() + four * a1.clone() + eight * b1.clone() + sixteen * a2 - b2
        // x1, y1, x2, y2 are all binary
            + a0.clone() * (one.clone() - a0)
            + b0.clone() * (one.clone() - b0)
            + a1.clone() * (one.clone() - a1)
            + b1.clone() * (one - b1)
    }

    /// additional gate
    pub(crate) fn add_gate(&self, meta: &mut VirtualCells<F>) -> Expression<F> {
        let a0 = meta.query_advice(self.a, Rotation::cur());
        let b0 = meta.query_advice(self.b, Rotation::cur());
        let a1 = meta.query_advice(self.a, Rotation::next());

        a0 + b0 - a1
    }

    /// additional gate
    pub(crate) fn mul_gate(&self, meta: &mut VirtualCells<F>) -> Expression<F> {
        let a0 = meta.query_advice(self.a, Rotation::cur());
        let b0 = meta.query_advice(self.b, Rotation::cur());
        let a1 = meta.query_advice(self.a, Rotation::next());

        a0 * b0 - a1
    }
}
