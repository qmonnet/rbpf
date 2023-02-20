use std::mem::size_of;

#[derive(Debug)]
pub struct Program {
    pub instructions: Vec<u8>
}

impl<'a> arbitrary::Arbitrary<'a> for Program {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Program {
            // Generate X amounts of u8s instead? Could be multiples of 8? Then check if 141 here?
            instructions: Vec::<u8>::from(Vec::<u8>::arbitrary(u)?)
        })
    }
    fn size_hint(_: usize) -> (usize, Option<usize>) {(
            size_of::<u8>() + size_of::<u16>() + size_of::<f64>() + size_of::<u16>(), // Lower bound, lowest is just 0
            None // None indicates no upper bound
        )
    }
}
