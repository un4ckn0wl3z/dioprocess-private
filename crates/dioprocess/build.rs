fn main() {
    // Embed the Windows manifest for UAC elevation
    let _ = embed_resource::compile("resources.rc", embed_resource::NONE);
}