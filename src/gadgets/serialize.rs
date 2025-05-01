use plonky2::field::extension::Extendable;
use plonky2::gates::constant::ConstantGate;
use plonky2::gates::coset_interpolation::CosetInterpolationGate;
use plonky2::gates::exponentiation::ExponentiationGate;
use plonky2::gates::lookup::LookupGate;
use plonky2::gates::lookup_table::LookupTableGate;
use plonky2::gates::multiplication_extension::MulExtensionGate;
use plonky2::gates::noop::NoopGate;
use plonky2::gates::poseidon::PoseidonGate;
use plonky2::gates::poseidon_mds::PoseidonMdsGate;
use plonky2::gates::public_input::PublicInputGate;
use plonky2::gates::random_access::RandomAccessGate;
use plonky2::gates::reducing::ReducingGate;
use plonky2::gates::reducing_extension::ReducingExtensionGate;
use plonky2::hash::hash_types::RichField;
use plonky2_u32::gates::add_many_u32::U32AddManyGate;
use plonky2_u32::gates::arithmetic_u32::U32ArithmeticGate;
use plonky2_u32::gates::comparison::ComparisonGate;
use plonky2_u32::gates::range_check_u32::U32RangeCheckGate;
use plonky2_u32::gates::subtraction_u32::U32SubtractionGate;

use plonky2::gates::arithmetic_base::ArithmeticGate;
use plonky2::gates::arithmetic_extension::ArithmeticExtensionGate;
use plonky2::gates::base_sum::BaseSumGate;
use plonky2::util::serialization::gate_serialization::GateSerializer;
use plonky2::{get_gate_tag_impl, impl_gate_serializer, read_gate_impl};

#[derive(Debug)]
pub struct RSAGateSerializer;
impl<F: RichField + Extendable<D>, const D: usize> GateSerializer<F, D> for RSAGateSerializer {
    impl_gate_serializer! {
        RSAGateSerializer,
        ArithmeticGate,
        ArithmeticExtensionGate<D>,
        BaseSumGate<2>,
        ConstantGate,
        CosetInterpolationGate<F, D>,
        ExponentiationGate<F, D>,
        LookupGate,
        LookupTableGate,
        MulExtensionGate<D>,
        NoopGate,
        PoseidonMdsGate<F, D>,
        PoseidonGate<F, D>,
        PublicInputGate,
        RandomAccessGate<F, D>,
        ReducingExtensionGate<D>,
        ReducingGate<D>,
        U32AddManyGate<F, D>,
        U32ArithmeticGate<F,D>,
        ComparisonGate<F,D>,
        U32RangeCheckGate<F,D>,
        U32SubtractionGate<F,D>
    }
}
