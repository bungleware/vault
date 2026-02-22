import { AlertTriangle } from "lucide-react";
import { Button } from "@/components/ui/button";
import BaseModal from "./BaseModal";
import ModalIcon from "./ModalIcon";
import { useNavigate } from "@tanstack/react-router";

interface ResetInstanceModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export default function ResetInstanceModal({
  isOpen,
  onClose,
}: ResetInstanceModalProps) {
  const navigate = useNavigate();

  const handleReset = () => {
    navigate({ to: "/reset-setup" });
    onClose();
  };

  const handleClose = () => {
    onClose();
  };

  return (
    <BaseModal isOpen={isOpen} onClose={handleClose} maxWidth="lg">
      <div className="p-6 md:p-8">
        <ModalIcon icon={AlertTriangle} variant="destructive" />

        <h2 className="text-2xl font-semibold text-white text-center mb-3">
          Reset Instance
        </h2>

        <div
          className="rounded-2xl border border-red-500/30 p-4 mb-6"
          style={{
            background:
              "linear-gradient(0deg, #2a1515 0%, rgba(40, 20, 20, 0.3) 100%)",
          }}
        >
          <p
            className="text-sm text-red-400 font-light leading-relaxed text-center"
            style={{ fontFamily: '"IBM Plex Mono", monospace' }}
          >
            This will permanently delete ALL data including all users,
            projects, tracks, and files. This action cannot be undone.
          </p>
        </div>

        <p className="text-sm text-muted-foreground text-center mb-6">
          You will be prompted to set up a new admin account on the next page.
        </p>

        <div className="flex flex-col gap-3">
          <Button
            onClick={handleReset}
            variant="destructive"
            className="w-full bg-[#381d1d] hover:bg-[#4a2626] border-[#7f3434] border-[0.5px] text-[#ff5656] font-medium"
          >
            Proceed to Reset
          </Button>
          <Button onClick={handleClose} className="w-full">
            Cancel
          </Button>
        </div>
      </div>
    </BaseModal>
  );
}
