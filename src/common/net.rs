use std::ptr;
use libc::{ifaddrs, getifaddrs};
use std::net::{IpAddr, Ipv4Addr};
use common::conversion;

static AF_INET: u16 = 2;

pub fn get_interface_ip(dev_name: &str) -> Option<IpAddr> {
    let mut r_ifaddrs: *mut ifaddrs = ptr::null_mut();
    
    let result = unsafe {
        getifaddrs(&mut r_ifaddrs)
    };
    if result == -1 {
        panic!("Could not get interface");
    }
    let mut p_ifa = r_ifaddrs;
    while !p_ifa.is_null() {
        let ifa = unsafe { *p_ifa };
        let name = conversion::cstr_to_str(ifa.ifa_name);
        if name == dev_name {
            let ifa_addr = unsafe { *ifa.ifa_addr };
            let sa_family = ifa_addr.sa_family;
            if sa_family == AF_INET {
                let u8_ip = ifa_addr.sa_data;
                let ipv4 = Ipv4Addr::new(u8_ip[2] as u8, u8_ip[3] as u8, u8_ip[4] as u8, u8_ip[5] as u8);
                return Some(IpAddr::V4(ipv4));
            }
        }
        p_ifa = ifa.ifa_next;
    }
    None
}

pub fn get_local_ips() -> Option<Vec<IpAddr>> {
    let mut r_ifaddrs: *mut ifaddrs = ptr::null_mut();
    let mut v_ips = Vec::with_capacity(4);
    
    let result = unsafe {
        getifaddrs(&mut r_ifaddrs)
    };
    if result == -1 {
        panic!("Could not get interface");
    }
    let mut p_ifa = r_ifaddrs;
    while !p_ifa.is_null() {
        let ifa = unsafe { *p_ifa };
        let ifa_addr = unsafe { *ifa.ifa_addr };
        let sa_family = ifa_addr.sa_family;
        if sa_family == AF_INET {
            let u8_ip = ifa_addr.sa_data;
            let ipv4 = Ipv4Addr::new(u8_ip[2] as u8, u8_ip[3] as u8, u8_ip[4] as u8, u8_ip[5] as u8);
            if !ipv4.is_loopback() {
                v_ips.push(IpAddr::V4(ipv4));
            }
        }
        p_ifa = ifa.ifa_next;
    }
    if v_ips.len() > 0 {
        return Some(v_ips);
    }
    None
}
