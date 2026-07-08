pub mod add;
pub mod change;
pub mod codesign;
pub mod delete;
pub mod install_id;
pub mod install_name;

use super::MachoCommand;
use arwen_macho::MachoError;

pub fn execute(macho: MachoCommand) -> Result<(), MachoError> {
    match macho {
        MachoCommand::DeleteRpath(args) => delete::execute(args),
        MachoCommand::ChangeRpath(args) => change::execute(args),
        MachoCommand::AddRpath(args) => add::execute(args),
        MachoCommand::ChangeInstallName(args) => install_name::execute(args),
        MachoCommand::ChangeInstallId(args) => install_id::execute(args),
        // Code signing has its own error type and is dispatched directly in
        // `cli::execute`.
        MachoCommand::AdhocSign(_) => unreachable!("AdhocSign is handled in cli::execute"),
    }
}
