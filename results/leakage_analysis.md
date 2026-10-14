# Data Leakage Analysis

This report documents every feature inspected for potential data leakage.
Features are classified as REMOVE (hard leakage) or FLAG (dataset-specific / 
conditional availability).

## Summary Table

| Feature | Decision | Reason |
|---------|----------|--------|
| FILENAME | REMOVE | Dataset-specific file identifier. Directly encodes the source file name, which i... |
| URL | REMOVE (use extracted features instead) | Raw URL string. If fed to a classical ML model, it allows memorisation of specif... |
| Domain | REMOVE (use DomainLength, NoOfSubDomain instead) | Raw domain string. Not a numeric feature; domain-level leakage could occur if th... |
| Title | REMOVE | Raw page title string. Text field requiring NLP processing. DomainTitleMatchScor... |
| TLD | REMOVE (use TLDLength instead) | Categorical string TLD. High cardinality; TLDLength is used as a numeric proxy.... |
| URLSimilarityIndex | FLAG (retained in full config; excluded in ablation config_c) | Computed by comparing the URL against a reference database of known URLs. This r... |
| TLDLegitimateProb | FLAG (retained in full config; excluded in ablation config_c) | Pre-computed probability of TLD legitimacy from a reference corpus. Dataset-coll... |
| URLCharProb | FLAG (retained in full config; excluded in ablation config_c) | Pre-computed character-level probability based on a reference corpus. Same conce... |
| DomainTitleMatchScore | FLAG (retained in full config; not available in live URL mode) | Requires fetching the live webpage to retrieve the page title, then computing a ... |
| URLTitleMatchScore | FLAG (retained in full config; not available in live URL mode) | Requires fetching the live webpage title and comparing against the URL. Same con... |

## Detailed Analysis

### FILENAME
- **Decision**: REMOVE
- **Reason**: Dataset-specific file identifier. Directly encodes the source file name, which is derived from the data collection process and is never available in real deployment.
- **Available in deployment**: False
- **Dataset-specific**: True

### URL
- **Decision**: REMOVE (use extracted features instead)
- **Reason**: Raw URL string. If fed to a classical ML model, it allows memorisation of specific URLs seen during training. URL-derived numeric features are used instead.
- **Available in deployment**: True
- **Dataset-specific**: False

### Domain
- **Decision**: REMOVE (use DomainLength, NoOfSubDomain instead)
- **Reason**: Raw domain string. Not a numeric feature; domain-level leakage could occur if the model memorises specific domain names. DomainLength and NoOfSubDomain are used as numeric proxies.
- **Available in deployment**: True
- **Dataset-specific**: False

### Title
- **Decision**: REMOVE
- **Reason**: Raw page title string. Text field requiring NLP processing. DomainTitleMatchScore uses it but that feature is flagged separately.
- **Available in deployment**: Only with webpage fetching
- **Dataset-specific**: False

### TLD
- **Decision**: REMOVE (use TLDLength instead)
- **Reason**: Categorical string TLD. High cardinality; TLDLength is used as a numeric proxy.
- **Available in deployment**: True
- **Dataset-specific**: False

### URLSimilarityIndex
- **Decision**: FLAG (retained in full config; excluded in ablation config_c)
- **Reason**: Computed by comparing the URL against a reference database of known URLs. This reference set is not generally available at deployment time and may encode information about the dataset collection process.
- **Available in deployment**: Only with external reference database
- **Dataset-specific**: True

### TLDLegitimateProb
- **Decision**: FLAG (retained in full config; excluded in ablation config_c)
- **Reason**: Pre-computed probability of TLD legitimacy from a reference corpus. Dataset-collection artifact that may not reflect the deployment distribution.
- **Available in deployment**: Only with reference corpus
- **Dataset-specific**: True

### URLCharProb
- **Decision**: FLAG (retained in full config; excluded in ablation config_c)
- **Reason**: Pre-computed character-level probability based on a reference corpus. Same concerns as TLDLegitimateProb.
- **Available in deployment**: Only with reference corpus
- **Dataset-specific**: True

### DomainTitleMatchScore
- **Decision**: FLAG (retained in full config; not available in live URL mode)
- **Reason**: Requires fetching the live webpage to retrieve the page title, then computing a similarity score against the domain. Not available in passive URL-only mode.
- **Available in deployment**: Only with safe webpage fetching
- **Dataset-specific**: False

### URLTitleMatchScore
- **Decision**: FLAG (retained in full config; not available in live URL mode)
- **Reason**: Requires fetching the live webpage title and comparing against the URL. Same concerns as DomainTitleMatchScore.
- **Available in deployment**: Only with safe webpage fetching
- **Dataset-specific**: False
