# syn2mas -  Synapse to Matrix Authentication Service

Tool to help with the migration of a Matrix Synapse installation to the Matrix Authentication Service.

The tool has two modes of operation:

- Advisor mode: Analyses the Synapse configuration and reports on any issues that would prevent a successful migration.
- Migration mode: Performs the migration of the Synapse database into the Matrix Authentication Service database.

## Usage

Pre-migration advisor:

```sh
npx @vector-im/syn2mas --command=advisor --synapseConfigFile homeserver.yaml
```
