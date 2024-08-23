# metadata module

had to do some weird stuff in order to pass the json `-x flag` to the functions

consequently, the there is no way to test the implementation "normally"

the current way to "test" it is to run

```sh
cargo run -- scan ./lib/src/modules/metadata/test.yar ./lib/src/modules/metadata/test.yar -x ./example.json
```

- exactly one file should match
