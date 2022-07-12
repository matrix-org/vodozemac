use afl::fuzz;
use vodozemac::megolm::{InboundGroupSession, InboundGroupSessionPickle, MegolmMessage};

const PICKLE: &str = "icxrnSCzUGKbrdzsn16BCzzWh+t+gbv5hlFNIFBJDDX+ksgy2Fw2eXoa3\
                      uILap4OnV/EsE5YOn859Tx4Qe0JFy4Bplntz5w/aLGA/99UBpNWUWHm1v\
                      +NP+9F/xFE2erlP1QQQIHXGiIDMHisQvb5N/4k0Tlio3oJHHW0nf627wn\
                      k2L5QERowaFEtrsrqbujc3a46I6nv/3i5sWfHBDy2pC6g1f94U1DqVLVN\
                      KZrUKbceGTZaLuH+yuzUtO9A58YlzjvOPNsNxw6VqEu4R036nZ58YJNsV\
                      8DF8sOAShu659ni9ijoOmSKJdUUBXA7jv/yO/V7w6+09ZaTykc+NlOBol\
                      MflZMnftlOdV5OAzRg0W/lMVBu9OSTplLbYsdLVCpvqcOavtXDQYAQZPy\
                      fAok9FHDXXqwCjX1UR0tQrR2zlEZ5AOXALYFTEwmnVBD9TNxsB2P4l9iS\
                      R8/OjaXCK4m39wXq/neOSUL8J35YYvkXgl97U4WVdu0NcznB9mscqm4MX\
                      IO8SjbOB/VkFgTjjme5ra2Kc766+OHaILptPardewN8voEZNr17zQmvuQ\
                      e7yInDtHPg14NJjsdxMWcwc0MLZgi0cOeqdKuoXYsHBMZc5kN5OX6qljR\
                      XOJUbygHkdGJTHig+36v0T33GQmlLY9BSA+IkLz5SJGnJUmgfjL2NInE2\
                      Bp5G36FQkitKy5HcfS20kYrZ++GswCUFjvB/J5FACaC8ERWZuDODF90GE\
                      cgbUefOgjjmKCaBYFCjoy0idVsYiM955f+qYILEc1Pb/NknpZicQrcrvZ\
                      cIeguKAfnoNqEfUE9xQ7H4Uh/4x+OmpqM5I6MhNKwD2bPjQ5g9QfTgWCr\
                      V0v4hiroOnkgRG1gWA048Xv2ZbdGibnPCDIoZEkaKt/PfGMjxOT8";

const PICKLE_KEY: &[u8; 32] = b"Default pickle key 1234567891012";

fn main() {
    let pickle = InboundGroupSessionPickle::from_encrypted(PICKLE, PICKLE_KEY)
        .expect("Our static pickle should always be decryptable");

    let mut session = InboundGroupSession::from_pickle(pickle);

    fuzz!(|data: &[u8]| {
        if let Ok(message) = MegolmMessage::try_from(data) {
            let message = message.into();
            let _ = session.decrypt(&message);
        }
    });
}
