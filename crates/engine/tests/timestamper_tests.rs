use que_engine as qe;

#[test]
fn parse_timestamper() {
    let t: qe::Timestamper = "digicert".parse().unwrap();
    let url = t.resolve().unwrap();
    assert!(url.starts_with("https://"));
    let t2: qe::Timestamper = "custom:https://tsa.example".parse().unwrap();
    assert_eq!(t2.resolve().unwrap(), "https://tsa.example");
}

#[test]
fn parse_timestamper_invalid() {
    let err = "bogus".parse::<qe::Timestamper>().unwrap_err();
    assert!(err.to_string().contains("Invalid timestamper"));
}



