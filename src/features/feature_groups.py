FEATURE_GROUPS = {
    "group_a_url_lexical": [
        "URLLength", "NoOfLettersInURL", "LetterRatioInURL",
        "NoOfDegitsInURL", "DegitRatioInURL",
        "NoOfEqualsInURL", "NoOfQMarkInURL", "NoOfAmpersandInURL",
        "NoOfOtherSpecialCharsInURL", "SpacialCharRatioInURL",
        "HasObfuscation", "NoOfObfuscatedChar", "ObfuscationRatio",
    ],
    "group_b_domain": [
        "DomainLength", "IsDomainIP", "TLDLength", "NoOfSubDomain",
    ],
    "group_c_protocol": [
        "IsHTTPS",
    ],
    "group_d_html_page": [
        "LineOfCode", "LargestLineLength", "HasTitle", "HasFavicon",
        "Robots", "IsResponsive", "HasDescription", "HasCopyrightInfo",
        "NoOfImage", "NoOfCSS", "NoOfJS",
    ],
    "group_e_form_login": [
        "HasExternalFormSubmit", "HasSubmitButton",
        "HasHiddenFields", "HasPasswordField",
    ],
    "group_f_redirect_ref": [
        "NoOfURLRedirect", "NoOfSelfRedirect", "NoOfPopup", "NoOfiFrame",
        "HasSocialNet", "Bank", "Pay", "Crypto",
        "NoOfSelfRef", "NoOfEmptyRef", "NoOfExternalRef",
    ],
    "group_g_dataset_specific": [
        "URLSimilarityIndex", "CharContinuationRate", "TLDLegitimateProb",
        "URLCharProb", "DomainTitleMatchScore", "URLTitleMatchScore",
    ],
}


def get_ablation_configs(available_features: list) -> dict:
    def intersect(group_keys):
        feats = []
        for k in group_keys:
            feats.extend(FEATURE_GROUPS.get(k, []))
        return [f for f in feats if f in available_features]

    return {
        "config_a_full": available_features,
        "config_b_url_domain_only": intersect([
            "group_a_url_lexical", "group_b_domain", "group_c_protocol"
        ]),
        "config_c_no_dataset_specific": intersect([
            "group_a_url_lexical", "group_b_domain", "group_c_protocol",
            "group_d_html_page", "group_e_form_login", "group_f_redirect_ref"
        ]),
    }
