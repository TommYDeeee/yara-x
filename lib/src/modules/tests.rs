/*! End-to-end tests. */
use goldenfile::Mint;
use ihex::Reader;
use protobuf::MessageDyn;
use std::fs;
use std::io::{Read, Write};
use std::path::Path;

macro_rules! create_binary_from_ihex {
    ($filename:expr) => {{
        let mut file = fs::File::open($filename).expect("Unable to open file");
        let mut contents = String::new();
        file.read_to_string(&mut contents).expect("Unable to read file");

        let mut reader = Reader::new(&contents);
        let mut data = Vec::new();
        while let Some(Ok(record)) = reader.next() {
            if let ihex::Record::Data { value, .. } = record {
                data.extend(value);
            }
        }

        Ok(data)
    }};
}

#[test]
fn test_modules() {
    // Create goldenfile mint
    let mut mint = Mint::new("src/modules");

    // Get all directories in "src/modules/"
    let module_dirs =
        fs::read_dir("src/modules").expect("Failed to read directory");

    // Iterate over the directories
    for dir in module_dirs {
        let dir = dir.expect("Failed to read directory entry");
        if dir.file_type().expect("Failed to get file type").is_dir() {
            // Get the name of the directory
            let module_name = dir
                .file_name()
                .into_string()
                .expect("Failed to convert OsString");

            // Skip the "protos" directory
            if module_name == "protos" {
                continue;
            }

            // Construct the rule
            let rule = format!(
                r#"
                import "{}"
                rule test {{
                    condition: false
                }}"#,
                module_name
            );

            // Compile the rule
            let rules = crate::compile(rule.as_str()).unwrap();
            let mut scanner = crate::scanner::Scanner::new(&rules);

            // Get all ".in" files in the directory
            let input_files = fs::read_dir(dir.path().join("tests/input"))
                .expect("Failed to read directory");
            for file in input_files {
                let file = file.expect("Failed to read directory entry");
                if file.file_type().expect("Failed to get file type").is_file()
                {
                    let file_path = file.path();
                    if file_path.extension()
                        == Some(Path::new("in").as_os_str())
                    {
                        // Read the ".in" file and create a binary from it
                        let data: Result<Vec<u8>, Box<dyn std::error::Error>> =
                            create_binary_from_ihex!(file_path
                                .to_str()
                                .unwrap());
                        let data = data.unwrap();

                        // Scan the data
                        let scan_results =
                            scanner.scan(&data).expect("scan should not fail");

                        // Get the module output
                        let output = scan_results
                            .module_output(&module_name)
                            .unwrap_or_else(|| {
                                panic!(
                                    "{} should produce some output",
                                    module_name
                                )
                            });

                        // Downcast the output
                        let output: &crate::modules::protos::macho::Macho =
                            <dyn MessageDyn>::downcast_ref(output).unwrap();

                        // Create a Goldenfile test
                        let mut output_file = mint
                            .new_goldenfile(format!(
                                "{}/tests/output/{}.out",
                                module_name,
                                file_path
                                    .file_stem()
                                    .unwrap()
                                    .to_str()
                                    .unwrap()
                            ))
                            .unwrap();
                        write!(output_file, "{:#?}", output).unwrap();
                    }
                }
            }
        }
    }
}
