use apple_device_tree::DeviceTreeNode;
use scroll::{ctx::TryFromCtx, Endian, Pwrite};

#[test]
fn deserialize_test() {
    let raspberry_pi_dtb = include_bytes!("rpi.dtb");

    let result = DeviceTreeNode::try_from_ctx(raspberry_pi_dtb, Endian::Little);

    assert!(result.is_ok());
    let (node, _) = result.unwrap();
    assert_eq!(node.properties.len(), 18);
    assert_eq!(node.children.len(), 18);
    assert_eq!(node.properties[0].name, "model");
}

#[test]
fn reserialize_test() {
    let raspberry_pi_dtb = include_bytes!("rpi.dtb");

    let result = DeviceTreeNode::try_from_ctx(raspberry_pi_dtb, Endian::Little);

    assert!(result.is_ok());
    let (node, _) = result.unwrap();

    let mut buffer = vec![0; raspberry_pi_dtb.len()];

    let mut offset = 0;

    let result = buffer.gwrite_with(&node, &mut offset, Endian::Little);

    if let Err(e) = &result {
        dbg!(e);
    }

    assert!(result.is_ok());
    assert_eq!(buffer.len(), raspberry_pi_dtb.len());
    assert_eq!(buffer, raspberry_pi_dtb);
}
