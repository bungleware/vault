import { AlertTriangle } from "lucide-react";
import { Button } from "@/components/ui/button";
import BaseModal from "./BaseModal";
import ModalIcon from "./ModalIcon";

interface LeaveTrackModalProps {
  isOpen: boolean;
  onClose: () => void;
  onConfirm: () => void;
  trackName: string;
  isLeaving?: boolean;
}

export default function LeaveTrackModal({
  isOpen,
  onClose,
  onConfirm,
  trackName,
  isLeaving = false,
}: LeaveTrackModalProps) {
  return (
    <BaseModal isOpen={isOpen} onClose={onClose} disableClose={isLeaving}>
      <div className="p-6 md:p-8">
        <ModalIcon icon={AlertTriangle} variant="destructive" />

        <h2 className="text-2xl font-semibold text-white text-center mb-3">
          Leave Track
        </h2>

        <p className="text-sm text-muted-foreground text-center mb-6">
          You will lose access to{" "}
          <span className="text-white font-medium">&quot;{trackName}&quot;</span>.
          You can request access again from the track owner if needed.
        </p>

        <div className="flex flex-col gap-3">
          <Button
            variant="destructive"
            onClick={onConfirm}
            disabled={isLeaving}
            className="w-full bg-[#381d1d] hover:bg-[#4a2626] border-[#7f3434] border-[0.5px] text-[#ff5656]"
          >
            {isLeaving ? "Leaving..." : "Leave Track"}
          </Button>
          <Button onClick={onClose} disabled={isLeaving} className="w-full">
            Cancel
          </Button>
        </div>
      </div>
    </BaseModal>
  );
}
