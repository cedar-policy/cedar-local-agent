# Benchmarking

## Data Generation

Data is generated from the data_gen bin. You can run it with:

```
cargo run --bin data_gen -- <file_name> <num_policies>
```

This supports producing a `.cedar` and a `.entities.json` file. You can see all the supported variations of a cedar policy in `data_gen/policy.rs`. 
Every permutation that can be made to the `PolicyRepr` struct and all the structs underneath it is supported. 

As of 11/29/23, there's no support for `when` or `unless` clauses being generated, and there's no support for the `in` operator. 
The `type_name` and `id` Strings are limited to `FIELD_LEN` characters which is set to `12` and the character set is lowercase letters.
The data generator creates separate entities for the principal, action, and resources. Parent/child entities are not supported. 

Additionally, when you ask for 1000 policies to be made, the program will actually generate n-1 policies (so 999 in this case) and append the following policy:

```
permit(
  principal == Principal::"request",
  action == Action::"request",
  resource == Resource::"request"
);
```

This policy will always result in an allow decision because generic forbid or permit everything policies are not allowed (see `policy.rs/generate_policy`). 
There are 32 randomly generated principals, actions, and resources each. 
Also, there are 3 extra entities added by the "request" policy bringing the total number of entities to 99, regardless of the number of policies. 

The data in the `data/` folder was generated with:

```
cargo run --bin data_gen -- 10 10
cargo run --bin data_gen -- 100 100
cargo run --bin data_gen -- 1000 1000
```

## Is_authorized Benchmark

This benchmark can be run with:
```
cargo bench -- is_authorized --verbose
```

The `is_authorized` benchmark uses the data in the `data/` folder with the request shown above. 
The benchmark will look for two files: `<num_policies>.cedar` and `<num_policies>.entities.json`.
`<num_policies>` is defined by `NUM_POLICIES_ARR` so that all the `is_authorized` benchmarks can be run at once and compared on the generated plots.
The generated plots are at:

```
cedar-local-agent/target/criterion/is_authorized/report/index.html
```

