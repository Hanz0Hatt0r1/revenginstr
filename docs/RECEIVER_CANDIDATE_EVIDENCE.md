# Receiver candidate evidence vector

`ReceiverCandidateEvidence/1` is the consumer-populated evidence contract for
one receiver candidate at one indirect call. It exposes the roadmap dimensions
as separate `supported`, `contradicted`, `unknown`, or `not_applicable` facts:

- exact vtable witness;
- constructor/factory witness;
- field/layout compatibility;
- slot compatibility;
- caller provenance;
- callgraph consistency;
- runtime witness.

Supported and contradicted facts require an evidence class and one or more
source-record references. Unknown and not-applicable facts must have a null
evidence class and no provenance rows. Reusing a source reference across
dimensions preserves correlation: consumers should not count it as independent
support more than once.

The schema deliberately has no aggregate score, probability, or automatic
decision field. Consumers own candidate identities and the evidence rows;
generic tools can validate and transport the vector without introducing
project-specific labels, thresholds, addresses, or class catalogs. The vector
does not authorize receiver transfer or affect routing.

See [`receiver-candidate-evidence-v1.schema.json`](../schemas/receiver-candidate-evidence-v1.schema.json)
for the exact wire contract.
