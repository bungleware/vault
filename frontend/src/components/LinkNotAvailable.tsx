import { Link2Off, ChevronLeft } from "lucide-react";
import { useNavigate } from "@tanstack/react-router";
import { Button } from "@/components/ui/button";
import { motion } from "motion/react";

export default function LinkNotAvailable() {
  const navigate = useNavigate();

  return (
    <div className="fixed inset-0 flex items-center justify-center p-4 z-[9999]" style={{ backgroundColor: "#181818" }}>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 0.4 }}
        className="text-center"
      >
        <div className="flex justify-center mb-6">
          <div className="w-20 h-20 rounded-full bg-white/10 flex items-center justify-center">
            <Link2Off className="size-10 text-white" />
          </div>
        </div>
        <h1 className="text-2xl font-semibold text-white mb-2">
          Link not available
        </h1>
        <p className="text-muted-foreground max-w-65 mb-8">
          It might have been removed or access may have changed
        </p>
        <Button
          onClick={() => navigate({ to: "/" })}
          variant="default"
          className="inline-flex items-center gap-2"
        >
          <ChevronLeft className="size-4" />
          Go back
        </Button>
      </motion.div>
    </div>
  );
}
