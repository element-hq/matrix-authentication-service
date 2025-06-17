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
  projectUrl: "https://localazy.com/p/matrix-authentication-service!v0.17",
  baseLocale: "en",
  languages: [
    {
      language: "cs",
      region: "",
      script: "",
      isRtl: false,
      name: "Czech",
      localizedName: "Čeština",
      pluralType: (n) => { return (n===1) ? "one" : (n>=2 && n<=4) ? "few" : "other"; }
    },
    {
      language: "da",
      region: "",
      script: "",
      isRtl: false,
      name: "Danish",
      localizedName: "Dansk",
      pluralType: (n) => { return (n===1) ? "one" : "other"; }
    },
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
      language: "fi",
      region: "",
      script: "",
      isRtl: false,
      name: "Finnish",
      localizedName: "Suomi",
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
      language: "hu",
      region: "",
      script: "",
      isRtl: false,
      name: "Hungarian",
      localizedName: "Magyar",
      pluralType: (n) => { return (n===1) ? "one" : "other"; }
    },
    {
      language: "nb",
      region: "NO",
      script: "",
      isRtl: false,
      name: "Norwegian Bokmål (Norway)",
      localizedName: "Norsk bokmål (Norge)",
      pluralType: (n) => { return (n===1) ? "one" : "other"; }
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
      language: "ru",
      region: "",
      script: "",
      isRtl: false,
      name: "Russian",
      localizedName: "Русский",
      pluralType: (n) => { return ((n%10===1) && (n%100!==11)) ? "one" : ((n%10>=2 && n%10<=4) && ((n%100<12 || n%100>14))) ? "few" : "many"; }
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
        "cs": "https://delivery.localazy.com/_a6918527916748535819d4adb076/_e0/7c203a8ac8bd48c3c4609a8effcd0fbac430f9b2/cs/frontend.json",
        "da": "https://delivery.localazy.com/_a6918527916748535819d4adb076/_e0/7c203a8ac8bd48c3c4609a8effcd0fbac430f9b2/da/frontend.json",
        "de": "https://delivery.localazy.com/_a6918527916748535819d4adb076/_e0/7c203a8ac8bd48c3c4609a8effcd0fbac430f9b2/de/frontend.json",
        "en": "https://delivery.localazy.com/_a6918527916748535819d4adb076/_e0/7c203a8ac8bd48c3c4609a8effcd0fbac430f9b2/en/frontend.json",
        "et": "https://delivery.localazy.com/_a6918527916748535819d4adb076/_e0/7c203a8ac8bd48c3c4609a8effcd0fbac430f9b2/et/frontend.json",
        "fi": "https://delivery.localazy.com/_a6918527916748535819d4adb076/_e0/7c203a8ac8bd48c3c4609a8effcd0fbac430f9b2/fi/frontend.json",
        "fr": "https://delivery.localazy.com/_a6918527916748535819d4adb076/_e0/7c203a8ac8bd48c3c4609a8effcd0fbac430f9b2/fr/frontend.json",
        "hu": "https://delivery.localazy.com/_a6918527916748535819d4adb076/_e0/7c203a8ac8bd48c3c4609a8effcd0fbac430f9b2/hu/frontend.json",
        "nb_NO": "https://delivery.localazy.com/_a6918527916748535819d4adb076/_e0/7c203a8ac8bd48c3c4609a8effcd0fbac430f9b2/nb-NO/frontend.json",
        "nl": "https://delivery.localazy.com/_a6918527916748535819d4adb076/_e0/7c203a8ac8bd48c3c4609a8effcd0fbac430f9b2/nl/frontend.json",
        "pt": "https://delivery.localazy.com/_a6918527916748535819d4adb076/_e0/7c203a8ac8bd48c3c4609a8effcd0fbac430f9b2/pt/frontend.json",
        "ru": "https://delivery.localazy.com/_a6918527916748535819d4adb076/_e0/7c203a8ac8bd48c3c4609a8effcd0fbac430f9b2/ru/frontend.json",
        "sv": "https://delivery.localazy.com/_a6918527916748535819d4adb076/_e0/7c203a8ac8bd48c3c4609a8effcd0fbac430f9b2/sv/frontend.json",
        "uk": "https://delivery.localazy.com/_a6918527916748535819d4adb076/_e0/7c203a8ac8bd48c3c4609a8effcd0fbac430f9b2/uk/frontend.json",
        "zh#Hans": "https://delivery.localazy.com/_a6918527916748535819d4adb076/_e0/7c203a8ac8bd48c3c4609a8effcd0fbac430f9b2/zh-Hans/frontend.json"
      }
    },
    {
      cdnHash: "5b69b0350dccfd47c245a5d41c1b9fdf6912cc6e",
      file: "file.json",
      path: "",
      cdnFiles: {
        "cs": "https://delivery.localazy.com/_a6918527916748535819d4adb076/_e0/5b69b0350dccfd47c245a5d41c1b9fdf6912cc6e/cs/file.json",
        "da": "https://delivery.localazy.com/_a6918527916748535819d4adb076/_e0/5b69b0350dccfd47c245a5d41c1b9fdf6912cc6e/da/file.json",
        "de": "https://delivery.localazy.com/_a6918527916748535819d4adb076/_e0/5b69b0350dccfd47c245a5d41c1b9fdf6912cc6e/de/file.json",
        "en": "https://delivery.localazy.com/_a6918527916748535819d4adb076/_e0/5b69b0350dccfd47c245a5d41c1b9fdf6912cc6e/en/file.json",
        "et": "https://delivery.localazy.com/_a6918527916748535819d4adb076/_e0/5b69b0350dccfd47c245a5d41c1b9fdf6912cc6e/et/file.json",
        "fi": "https://delivery.localazy.com/_a6918527916748535819d4adb076/_e0/5b69b0350dccfd47c245a5d41c1b9fdf6912cc6e/fi/file.json",
        "fr": "https://delivery.localazy.com/_a6918527916748535819d4adb076/_e0/5b69b0350dccfd47c245a5d41c1b9fdf6912cc6e/fr/file.json",
        "hu": "https://delivery.localazy.com/_a6918527916748535819d4adb076/_e0/5b69b0350dccfd47c245a5d41c1b9fdf6912cc6e/hu/file.json",
        "nb_NO": "https://delivery.localazy.com/_a6918527916748535819d4adb076/_e0/5b69b0350dccfd47c245a5d41c1b9fdf6912cc6e/nb-NO/file.json",
        "nl": "https://delivery.localazy.com/_a6918527916748535819d4adb076/_e0/5b69b0350dccfd47c245a5d41c1b9fdf6912cc6e/nl/file.json",
        "pt": "https://delivery.localazy.com/_a6918527916748535819d4adb076/_e0/5b69b0350dccfd47c245a5d41c1b9fdf6912cc6e/pt/file.json",
        "ru": "https://delivery.localazy.com/_a6918527916748535819d4adb076/_e0/5b69b0350dccfd47c245a5d41c1b9fdf6912cc6e/ru/file.json",
        "sv": "https://delivery.localazy.com/_a6918527916748535819d4adb076/_e0/5b69b0350dccfd47c245a5d41c1b9fdf6912cc6e/sv/file.json",
        "uk": "https://delivery.localazy.com/_a6918527916748535819d4adb076/_e0/5b69b0350dccfd47c245a5d41c1b9fdf6912cc6e/uk/file.json",
        "zh#Hans": "https://delivery.localazy.com/_a6918527916748535819d4adb076/_e0/5b69b0350dccfd47c245a5d41c1b9fdf6912cc6e/zh-Hans/file.json"
      }
    }
  ]
};

export default localazyMetadata;