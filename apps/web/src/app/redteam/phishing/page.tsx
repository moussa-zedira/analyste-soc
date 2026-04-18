import PhishingCampaigns from "./PhishingCampaigns";

export const metadata = {
  title: "Phishing Campaigns — Red Team",
  description:
    "Workflow GoPhish enrichi: persistance + sync + analytics + audit MITRE T1566.",
};

export default function Page() {
  return <PhishingCampaigns />;
}
