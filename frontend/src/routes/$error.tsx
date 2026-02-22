import { createFileRoute } from "@tanstack/react-router";
import LinkNotAvailable from "@/components/LinkNotAvailable";

export const Route = createFileRoute("/$error")({
  component: NotFoundPage,
});

function NotFoundPage() {
  return <LinkNotAvailable />;
}
