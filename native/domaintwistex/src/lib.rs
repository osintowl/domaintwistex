use rustler::{Encoder, Env, NifResult, Term};
use twistrs::permutate::Domain;
use std::collections::HashSet;

mod atoms {
    rustler::atoms! {
        fqdn,
        tld,
        kind,
        resolvable,
        ips
    }
}

#[rustler::nif]
fn generate_permutations<'a>(env: Env<'a>, domain_str: String) -> NifResult<Term<'a>> {
    let domain = match Domain::new(&domain_str) {
        Ok(d) => d,
        Err(_) => return Ok(Vec::<Term>::new().encode(env)),
    };

    let perms = match domain.all() {
        Ok(p) => p.collect::<HashSet<_>>().into_iter().collect::<Vec<_>>(),
        Err(_) => return Ok(Vec::<Term>::new().encode(env)),
    };

    let results: Vec<Term> = perms
        .iter()
        .map(|p| {
            let map = Term::map_new(env);
            map.map_put(atoms::fqdn(), &p.domain.fqdn).unwrap()
               .map_put(atoms::tld(), &p.domain.tld).unwrap()
               .map_put(atoms::kind(), format!("{:?}", p.kind)).unwrap()
        })
        .collect();

    Ok(results.encode(env))
}

rustler::init!(
    "Elixir.DomainTwistex",
    [
        generate_permutations
    ]
);
