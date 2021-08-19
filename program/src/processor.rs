//! Program state processor

use {
    crate::{instruction::*, state::*, *},
    solana_program::{
        account_info::{next_account_info, AccountInfo},
        clock::Clock,
        entrypoint::ProgramResult,
        feature::{self, Feature},
        msg,
        program::{invoke, invoke_signed},
        program_error::ProgramError,
        program_pack::Pack,
        pubkey::Pubkey,
        rent::Rent,
        system_instruction,
        sysvar::Sysvar,
    },
};

/// Instruction processor
pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    input: &[u8],
) -> ProgramResult {
    let instruction = ConfidentialTokenInstruction::unpack_from_slice(input)?;
    let account_info_iter = &mut accounts.iter();

    match instruction {
        _ => todo!(),
    }

    Ok(())
}
