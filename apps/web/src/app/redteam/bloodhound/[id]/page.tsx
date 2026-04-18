import DatasetView from "./DatasetView";

export const metadata = {
  title: "BloodHound Dataset — Red Team",
};

export default async function Page({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  return <DatasetView datasetId={id} />;
}
