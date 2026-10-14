PHISIUIIL_NUMERIC_FEATURES = [
    "URLLength", "NoOfLettersInURL", "LetterRatioInURL",
    "NoOfDegitsInURL", "DegitRatioInURL",
    "NoOfEqualsInURL", "NoOfQMarkInURL", "NoOfAmpersandInURL",
    "NoOfOtherSpecialCharsInURL", "SpacialCharRatioInURL",
    "HasObfuscation", "NoOfObfuscatedChar", "ObfuscationRatio",
    "DomainLength", "IsDomainIP", "TLDLength", "NoOfSubDomain",
    "IsHTTPS",
    "LineOfCode", "LargestLineLength", "HasTitle", "HasFavicon",
    "Robots", "IsResponsive", "HasDescription", "HasCopyrightInfo",
    "NoOfImage", "NoOfCSS", "NoOfJS",
    "HasExternalFormSubmit", "HasSubmitButton", "HasHiddenFields", "HasPasswordField",
    "NoOfURLRedirect", "NoOfSelfRedirect", "NoOfPopup", "NoOfiFrame",
    "HasSocialNet", "Bank", "Pay", "Crypto",
    "NoOfSelfRef", "NoOfEmptyRef", "NoOfExternalRef",
    "URLSimilarityIndex", "CharContinuationRate", "TLDLegitimateProb",
    "URLCharProb", "DomainTitleMatchScore", "URLTitleMatchScore",
]

URL_ONLY_FEATURES = [
    "URLLength", "NoOfLettersInURL", "LetterRatioInURL",
    "NoOfDegitsInURL", "DegitRatioInURL",
    "NoOfEqualsInURL", "NoOfQMarkInURL", "NoOfAmpersandInURL",
    "NoOfOtherSpecialCharsInURL", "SpacialCharRatioInURL",
    "HasObfuscation", "NoOfObfuscatedChar", "ObfuscationRatio",
    "DomainLength", "IsDomainIP", "TLDLength", "NoOfSubDomain",
    "IsHTTPS",
]

DATASET_SPECIFIC_FEATURES = [
    "URLSimilarityIndex", "CharContinuationRate", "TLDLegitimateProb",
    "URLCharProb", "DomainTitleMatchScore", "URLTitleMatchScore",
]

LEAKAGE_REMOVE  = ["FILENAME", "URL", "Domain", "Title", "TLD"]
TARGET_COLUMN   = "label"
LABEL_MAP       = {0: "Legitimate", 1: "Phishing", 2: "Scam"}
LABEL_MAP_BINARY= {0: "Legitimate", 1: "Phishing"}
