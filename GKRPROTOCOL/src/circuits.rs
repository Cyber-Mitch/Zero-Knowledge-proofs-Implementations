use std::ops::{Add, Mul};

use ark_ff::Field;
use ark_poly::{DenseMultilinearExtension, MultilinearExtension};

/// A type of a gate in the Circuit.
#[derive(Copy, Clone, PartialEq, Eq)]
pub enum GateType {
    /// An addition gate.
    Add,
    /// A multiplication gate.
    Mul,
}

/// A gate in the Circuit.
#[derive(Clone, Copy)]
pub struct Gate {
    /// The type of the gate.
    ttype: GateType,
    /// Two inputs, indexes into the previous layer gates’ outputs.
    inputs: [usize; 2],
}

impl Gate {
    /// Create a new `Gate`.
    pub fn new(ttype: GateType, inputs: [usize; 2]) -> Self {
        Self { ttype, inputs }
    }
}

/// A layer of gates in the circuit.
#[derive(Clone)]
pub struct CircuitLayer {
    layer: Vec<Gate>,
}

impl CircuitLayer {
    /// Create a new `CircuitLayer`.
    pub fn new(layer: Vec<Gate>) -> Self {
        Self { layer }
    }

    /// The number of gates in the layer.
    pub fn len(&self) -> usize {
        self.layer.len()
    }

    pub fn is_empty(&self) -> bool {
        self.layer.is_empty()
    }
}


pub struct CircuitEvaluation<F> {
    /// Evaluations on a per-layer basis.
    pub layers: Vec<Vec<F>>,
}

impl<F: Copy> CircuitEvaluation<F> {
    /// Returns the value corresponding to a gate at a specific layer.
    pub fn w(&self, layer: usize, label: usize) -> F {
        self.layers[layer][label]
    }
}

/// The circuit in layered form.
#[derive(Clone)]
pub struct Circuit {
    /// First layer being the output layer, last layer being the input layer.
    layers: Vec<CircuitLayer>,
    /// Number of inputs.
    num_inputs: usize,
}

impl Circuit {
    pub fn new(layers: Vec<CircuitLayer>, num_inputs: usize) -> Self {
        Self { layers, num_inputs }
    }

    pub fn num_vars_at(&self, layer: usize) -> Option<usize> {
        let num_gates = if let Some(layer) = self.layers.get(layer) {
            layer.len()
        } else if layer == self.layers.len() {
            self.num_inputs
        } else {
            return None;
        };
        Some((num_gates as u64).trailing_zeros() as usize)
    }

    /// Evaluate a `Circuit` on a given input.
    pub fn evaluate<F>(&self, input: &[F]) -> CircuitEvaluation<F>
    where
        F: Add<Output = F> + Mul<Output = F> + Copy,
    {
        // Reserve enough space for all layers.
        let mut layers = Vec::with_capacity(self.layers.len() + 1);
        layers.push(input.to_vec());

        // Process from input layer to output layer by iterating in reverse order
        // of the stored layers.
        for layer in self.layers.iter().rev() {
            // Get the most recent layer's evaluations.
            let current = layers.last().unwrap();
            let next_layer: Vec<F> = layer
                .layer
                .iter()
                .map(|gate| match gate.ttype {
                    GateType::Add => current[gate.inputs[0]] + current[gate.inputs[1]],
                    GateType::Mul => current[gate.inputs[0]] * current[gate.inputs[1]],
                })
                .collect();
            layers.push(next_layer);
        }

        // Reverse to have the output layer first, then intermediary layers, then inputs.
        layers.reverse();
        CircuitEvaluation { layers }
    }

    /// The add_i(a, b, c) predicate at layer i.
    pub fn add_i(&self, i: usize, a: usize, b: usize, c: usize) -> bool {
        let gate = &self.layers[i].layer[a];
        gate.ttype == GateType::Add && gate.inputs[0] == b && gate.inputs[1] == c
    }

    /// The mul_i(a, b, c) predicate at layer i.
    pub fn mul_i(&self, i: usize, a: usize, b: usize, c: usize) -> bool {
        let gate = &self.layers[i].layer[a];
        gate.ttype == GateType::Mul && gate.inputs[0] == b && gate.inputs[1] == c
    }

    pub fn layers(&self) -> &[CircuitLayer] {
        &self.layers
    }

    pub fn num_outputs(&self) -> usize {
        self.layers[0].layer.len()
    }

    pub fn num_inputs(&self) -> usize {
        self.num_inputs
    }

    /// Constructs the add_i extension polynomial at layer i.
    pub fn add_i_ext<F: Field>(&self, r_i: &[F], i: usize) -> DenseMultilinearExtension<F> {
        let num_vars_current = f64::from(self.layers[i].len() as u32).log2() as usize;
        let num_vars_next = f64::from(
            self.layers
                .get(i + 1)
                .map(|c| c.len())
                .unwrap_or(self.num_inputs) as u32,
        )
        .log2() as usize;
        let n_current = 1 << num_vars_current;
        let n_next = 1 << num_vars_next;
        let cap = n_current * n_next * n_next;
        let mut add_i = Vec::with_capacity(cap);

        for c in 0..n_next {
            for b in 0..n_next {
                for a in 0..n_current {
                    add_i.push(if self.add_i(i, a, b, c) {
                        F::one()
                    } else {
                        F::zero()
                    });
                }
            }
        }

        let add_i = DenseMultilinearExtension::from_evaluations_vec(
            num_vars_current + num_vars_next * 2,
            add_i,
        );
        add_i.fix_variables(r_i)
    }

    /// Constructs the mul_i extension polynomial at layer i.
    pub fn mul_i_ext<F: Field>(&self, r_i: &[F], i: usize) -> DenseMultilinearExtension<F> {
        let num_vars_current = f64::from(self.layers[i].len() as u32).log2() as usize;
        let num_vars_next = f64::from(
            self.layers
                .get(i + 1)
                .map(|c| c.len())
                .unwrap_or(self.num_inputs) as u32,
        )
        .log2() as usize;
        let n_current = 1 << num_vars_current;
        let n_next = 1 << num_vars_next;
        let cap = n_current * n_next * n_next;
        let mut mul_i = Vec::with_capacity(cap);

        for c in 0..n_next {
            for b in 0..n_next {
                for a in 0..n_current {
                    mul_i.push(if self.mul_i(i, a, b, c) {
                        F::one()
                    } else {
                        F::zero()
                    });
                }
            }
        }

        let mul_i = DenseMultilinearExtension::from_evaluations_vec(
            num_vars_current + num_vars_next * 2,
            mul_i,
        );
        mul_i.fix_variables(r_i)
    }
}

#[cfg(test)]
pub(crate) fn circuit() -> Circuit {
    Circuit {
        layers: vec![
            CircuitLayer {
                layer: vec![
                    Gate {
                        ttype: GateType::Mul,
                        inputs: [0, 1],
                    },
                    Gate {
                        ttype: GateType::Mul,
                        inputs: [2, 3],
                    },
                ],
            },
            CircuitLayer {
                layer: vec![
                    Gate {
                        ttype: GateType::Mul,
                        inputs: [0, 0],
                    },
                    Gate {
                        ttype: GateType::Mul,
                        inputs: [1, 1],
                    },
                    Gate {
                        ttype: GateType::Mul,
                        inputs: [1, 2],
                    },
                    Gate {
                        ttype: GateType::Mul,
                        inputs: [3, 3],
                    },
                ],
            },
        ],
        num_inputs: 4,
    }
}

#[cfg(test)]
mod tests {
    use super::circuit;

    #[test]
    fn circuit_test() {
        let circuit = circuit_from_book();
        let layers = circuit.evaluate(&[3, 2, 3, 1]);
        assert_eq!(
            layers.layers,
            vec![vec![36, 6], vec![9, 4, 6, 1], vec![3, 2, 3, 1]]
        );

        // Test that mul_1 evaluates as expected.
        for a in 0..4 {
            for b in 0..4 {
                for c in 0..4 {
                    let expected = ((a == 0 || a == 1) && a == b && a == c)
                        || (a == 2 && b == 1 && c == 2)
                        || (a == b && b == c && a == 3);
                    assert_eq!(circuit.mul_i(1, a, b, c), expected, "{a} {b} {c}");
                }
            }
        }
    }
}
