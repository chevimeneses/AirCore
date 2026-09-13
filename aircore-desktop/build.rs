fn main() {
    #[cfg(target_os = "windows")]
    {
        let mut res = winres::WindowsResource::new();
        res.set_icon("aircore.ico");
        res.compile().expect("no se pudo incrustar el ícono en el .exe");
    }
}