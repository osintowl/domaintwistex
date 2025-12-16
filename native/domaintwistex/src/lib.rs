use rustler::NifResult;
use std::collections::HashSet;
use twistrs::permutate::Domain;
use twistrs::filter::Permissive;

#[derive(rustler::NifMap)]
struct Result {
    fqdn: String,
    tld: String,
    kind: String,
}

#[rustler::nif]
fn generate_permutations(domain_str: String) -> NifResult<Vec<Result>> {
    let domain = match Domain::new(&domain_str) {
        Ok(d) => d,
        Err(_) => return Ok(Default::default()),
    };

    // twistrs 0.9: all() takes a filter and returns iterator directly
    let perms: HashSet<_> = domain.all(&Permissive).collect();

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

rustler::init!("Elixir.DomainTwistex.Utils");
