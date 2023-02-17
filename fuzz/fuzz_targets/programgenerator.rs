#[derive(Debug)]
pub struct Program {
    pub instructions: Vec<u8>
}

impl<'a> arbitrary::Arbitrary<'a> for Program {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Program {
            instructions: Vec::<u8>::from(Vec::<u8>::arbitrary(u)?)
        })
    }
    fn size_hint(_: usize) -> (usize, Option<usize>) {
        (0, None)
    }
}
