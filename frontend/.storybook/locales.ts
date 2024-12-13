export type LocalazyLanguage = {
    language: string;
    region: string;
    script: string;
    isRtl: boolean;
    localizedName: string;
    name: string;
    aliasOf?: string | null | undefined;
    expansionOf?: string | null | undefined;
    pluralType: (n: number) => "zero" | "one" | "two" | "many" | "few" | "other";
};
export type LocalazyFile = {
    cdnHash: string;
    file: string;
    path: string;
    library?: string | null | undefined;
    module?: string | null | undefined;
    buildType?: string | null | undefined;
    productFlavors?: string[] | null | undefined;
    cdnFiles: { [lang:string]: string };
};
export type LocalazyMetadata = {
    projectUrl: string;
    baseLocale: string;
    languages: LocalazyLanguage[];
    files: LocalazyFile[];
};
             
const localazyMetadata: LocalazyMetadata = {
  projectUrl: "https://localazy.com/p/matrix-authentication-service",
  baseLocale: "en",
  languages: [
    {
      language: "de",
      region: "",
      script: "",
      isRtl: false,
      name: "German",
      localizedName: "Deutsch",
      pluralType: (n) => { return (n===1) ? "one" : "other"; }
    },
    {
      language: "en",
      region: "",
      script: "",
      isRtl: false,
      name: "English",
      localizedName: "English",
      pluralType: (n) => { return (n===1) ? "one" : "other"; }
    },
    {
      language: "et",
      region: "",
      script: "",
      isRtl: false,
      name: "Estonian",
      localizedName: "Eesti",
      pluralType: (n) => { return (n===1) ? "one" : "other"; }
    },
    {
      language: "fr",
      region: "",
      script: "",
      isRtl: false,
      name: "French",
      localizedName: "Français",
      pluralType: (n) => { return (n===0 || n===1) ? "one" : "other"; }
    },
    {
      language: "nl",
      region: "",
      script: "",
      isRtl: false,
      name: "Dutch",
      localizedName: "Nederlands",
      pluralType: (n) => { return (n===1) ? "one" : "other"; }
    },
    {
      language: "pt",
      region: "",
      script: "",
      isRtl: false,
      name: "Portuguese",
      localizedName: "Português",
      pluralType: (n) => { return (n>=0 && n<=1) ? "one" : "other"; }
    },
    {
      language: "sv",
      region: "",
      script: "",
      isRtl: false,
      name: "Swedish",
      localizedName: "Svenska",
      pluralType: (n) => { return (n===1) ? "one" : "other"; }
    },
    {
      language: "uk",
      region: "",
      script: "",
      isRtl: false,
      name: "Ukrainian",
      localizedName: "Українська",
      pluralType: (n) => { return ((n%10===1) && (n%100!==11)) ? "one" : ((n%10>=2 && n%10<=4) && ((n%100<12 || n%100>14))) ? "few" : "many"; }
    },
    {
      language: "zh",
      region: "",
      script: "Hans",
      isRtl: false,
      name: "Simplified Chinese",
      localizedName: "简体中文",
      pluralType: (n) => { return "other"; }
    }
  ],
  files: [
    {
      cdnHash: "7c203a8ac8bd48c3c4609a8effcd0fbac430f9b2",
      file: "frontend.json",
      path: "",
      cdnFiles: {
        "de": "https://delivery.localazy.com/_a7686032324574572744739e0707/_e0/7c203a8ac8bd48c3c4609a8effcd0fbac430f9b2/de/frontend.json",
        "en": "https://delivery.localazy.com/_a7686032324574572744739e0707/_e0/7c203a8ac8bd48c3c4609a8effcd0fbac430f9b2/en/frontend.json",
        "et": "https://delivery.localazy.com/_a7686032324574572744739e0707/_e0/7c203a8ac8bd48c3c4609a8effcd0fbac430f9b2/et/frontend.json",
        "fr": "https://delivery.localazy.com/_a7686032324574572744739e0707/_e0/7c203a8ac8bd48c3c4609a8effcd0fbac430f9b2/fr/frontend.json",
        "nl": "https://delivery.localazy.com/_a7686032324574572744739e0707/_e0/7c203a8ac8bd48c3c4609a8effcd0fbac430f9b2/nl/frontend.json",
        "pt": "https://delivery.localazy.com/_a7686032324574572744739e0707/_e0/7c203a8ac8bd48c3c4609a8effcd0fbac430f9b2/pt/frontend.json",
        "sv": "https://delivery.localazy.com/_a7686032324574572744739e0707/_e0/7c203a8ac8bd48c3c4609a8effcd0fbac430f9b2/sv/frontend.json",
        "uk": "https://delivery.localazy.com/_a7686032324574572744739e0707/_e0/7c203a8ac8bd48c3c4609a8effcd0fbac430f9b2/uk/frontend.json",
        "zh#Hans": "https://delivery.localazy.com/_a7686032324574572744739e0707/_e0/7c203a8ac8bd48c3c4609a8effcd0fbac430f9b2/zh-Hans/frontend.json"
      }
    },
    {
      cdnHash: "5b69b0350dccfd47c245a5d41c1b9fdf6912cc6e",
      file: "file.json",
      path: "",
      cdnFiles: {
        "de": "https://delivery.localazy.com/_a7686032324574572744739e0707/_e0/5b69b0350dccfd47c245a5d41c1b9fdf6912cc6e/de/file.json",
        "en": "https://delivery.localazy.com/_a7686032324574572744739e0707/_e0/5b69b0350dccfd47c245a5d41c1b9fdf6912cc6e/en/file.json",
        "et": "https://delivery.localazy.com/_a7686032324574572744739e0707/_e0/5b69b0350dccfd47c245a5d41c1b9fdf6912cc6e/et/file.json",
        "fr": "https://delivery.localazy.com/_a7686032324574572744739e0707/_e0/5b69b0350dccfd47c245a5d41c1b9fdf6912cc6e/fr/file.json",
        "nl": "https://delivery.localazy.com/_a7686032324574572744739e0707/_e0/5b69b0350dccfd47c245a5d41c1b9fdf6912cc6e/nl/file.json",
        "pt": "https://delivery.localazy.com/_a7686032324574572744739e0707/_e0/5b69b0350dccfd47c245a5d41c1b9fdf6912cc6e/pt/file.json",
        "sv": "https://delivery.localazy.com/_a7686032324574572744739e0707/_e0/5b69b0350dccfd47c245a5d41c1b9fdf6912cc6e/sv/file.json",
        "uk": "https://delivery.localazy.com/_a7686032324574572744739e0707/_e0/5b69b0350dccfd47c245a5d41c1b9fdf6912cc6e/uk/file.json",
        "zh#Hans": "https://delivery.localazy.com/_a7686032324574572744739e0707/_e0/5b69b0350dccfd47c245a5d41c1b9fdf6912cc6e/zh-Hans/file.json"
      }
    }
  ]
};

export default localazyMetadata;