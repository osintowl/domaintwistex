use rustler::NifResult;
use std::collections::HashSet;
use twistrs::permutate::Domain;

// 1. Rustler has builtin support for maps with atom keys
// -------------------------------------------------------
#[derive(rustler::NifMap)]
struct Result {
    fqdn: String,
    tld: String,
    kind: String,
}

// 2. You can return anything that is convertible to a Term, you don't need to do inline encoding (and thus don't need `env`, together with `NifMap`)
// ------------------------------------------
#[rustler::nif]
fn generate_permutations(domain_str: String) -> NifResult<Vec<Result>> {
    let domain = match Domain::new(&domain_str) {
        Ok(d) => d,
        Err(_) => return Ok(Default::default()),
    };

    // 3. No need to convert the HashSet into a Vec if you just want to
    //    iterate over it again
    // -----------------------------------------
    let perms = match domain.all() {
        Ok(p) => p.collect::<HashSet<_>>(),
        Err(_) => return Ok(Default::default()),
    };

    let results = perms
        .iter()
        .map(|p| Result {
            fqdn: p.domain.fqdn.clone(),
            tld: p.domain.tld.clone(),
            kind: format!("{:?}", p.kind),
        })
        .collect();

    Ok(results)
}

rustler::init!("Elixir.DomainTwistex.Utils", [generate_permutations]);
// Huge thanks to filmor from elixirforum.com for fixing my terrible rust code!
