use std::cmp;
use ark_ff::{FftField, Field};
use ark_poly::{
    univariate, DenseMultilinearExtension, EvaluationDomain, Evaluations, GeneralEvaluationDomain,
    MultilinearExtension,
};
use sum_check_protocol::SumCheckPolynomial;


#[derive(Clone)]
pub struct W<F: Field> {
    add_i: DenseMultilinearExtension<F>,
    mul_i: DenseMultilinearExtension<F>,
    w_b: DenseMultilinearExtension<F>,
    w_c: DenseMultilinearExtension<F>,
}

impl<F: Field> W<F> {
    /// Create a new `W` polynomial.
    #[inline]
    pub fn new(
        add_i: DenseMultilinearExtension<F>,
        mul_i: DenseMultilinearExtension<F>,
        w_b: DenseMultilinearExtension<F>,
        w_c: DenseMultilinearExtension<F>,
    ) -> Self {
        Self { add_i, mul_i, w_b, w_c }
    }
}

impl<F: FftField> SumCheckPolynomial<F> for W<F> {
    #[inline]
    fn evaluate(&self, point: &[F]) -> Option<F> {
        // Split the point into b and c parts.
        let (b, c) = point.split_at(self.w_b.num_vars);
        let add_e = self.add_i.evaluate(point)?;
        let mul_e = self.mul_i.evaluate(point)?;
        let w_b_val = self.w_b.evaluate(b)?;
        let w_c_val = self.w_c.evaluate(c)?;

        Some(add_e * (w_b_val + w_c_val) + mul_e * (w_b_val * w_c_val))
    }

    #[inline]
    fn fix_variables(&self, partial_point: &[F]) -> Self {
        let b_vars = self.w_b.num_vars;
        let b_partial = &partial_point[..partial_point.len().min(b_vars)];
        let c_partial = if partial_point.len() > b_vars {
            &partial_point[b_vars..]
        } else {
            &[]
        };

        Self {
            add_i: self.add_i.fix_variables(partial_point),
            mul_i: self.mul_i.fix_variables(partial_point),
            w_b: self.w_b.fix_variables(b_partial),
            w_c: self.w_c.fix_variables(c_partial),
        }
    }

    fn to_univariate(&self) -> univariate::SparsePolynomial<F> {
        let domain = GeneralEvaluationDomain::new(3).unwrap();

        let evals: Vec<F> = domain
            .elements()
            .map(|e| self.fix_variables(&[e]).to_evaluations().into_iter().sum())
            .collect();

        let evaluations = Evaluations::from_vec_and_domain(evals, domain);
        let p = evaluations.interpolate();
        p.into()
    }

    #[inline]
    fn num_vars(&self) -> usize {
        self.add_i.num_vars()
    }

    fn to_evaluations(&self) -> Vec<F> {
        let w_b_evals = self.w_b.to_evaluations();
        let w_c_evals = self.w_c.to_evaluations();
        let add_i_evals = self.add_i.to_evaluations();
        let mul_i_evals = self.mul_i.to_evaluations();

        let n_b = w_b_evals.len();
        let n_c = w_c_evals.len();
        let mut res = Vec::with_capacity(n_b * n_c);

        for (b_idx, &w_b_item) in w_b_evals.iter().enumerate() {
            for (c_idx, &w_c_item) in w_c_evals.iter().enumerate() {
                let bc_idx = idx(c_idx, b_idx, self.w_b.num_vars);
                res.push(
                    add_i_evals[bc_idx] * (w_b_item + w_c_item)
                        + mul_i_evals[bc_idx] * (w_b_item * w_c_item),
                );
            }
        }
        res
    }
}

#[inline]
fn idx(i: usize, j: usize, num_vars: usize) -> usize {
    (i << num_vars) | j
}
