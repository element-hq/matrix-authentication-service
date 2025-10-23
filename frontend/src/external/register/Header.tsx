import { useTranslation } from "react-i18next";

const Header = ({ icon, titleKey }) => {
  const { t } = useTranslation();

  return (
    <header className="page-heading">
      <div className="icon">{icon}</div>
      <div className="header">
        <h1 className="title">{t(titleKey)}</h1>
      </div>
    </header>
  );
};

export default Header;
