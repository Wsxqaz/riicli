use crate::recon::get_computer_detail;
use crate::winapi::ad::query_users;

pub async fn run() {
    log::info!("recon_bin");

    let computer_details = get_computer_detail::run();
    log::info!("computer_details: {:?}", computer_details);

    let users = query_users();
    log::info!("users: {:?}", users);
}
