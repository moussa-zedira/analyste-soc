import CampaignDetail from "./CampaignDetail";

export const metadata = {
  title: "Phishing Campaign — Red Team",
};

export default async function Page({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  return <CampaignDetail campaignId={id} />;
}
