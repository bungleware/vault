import { Download } from "lucide-react";
import { Button } from "@/components/ui/button";
import BaseModal from "./BaseModal";
import ModalIcon from "./ModalIcon";
import { exportInstance } from "@/api/instance";
import { useState } from "react";

interface ExportInstanceModalProps {
  isOpen: boolean;
  onClose: () => void;
  estimatedSizeGB?: number;
}

export default function ExportInstanceModal({
  isOpen,
  onClose,
  estimatedSizeGB,
}: ExportInstanceModalProps) {
  const [isExporting, setIsExporting] = useState(false);

  const handleExport = async () => {
    try {
      setIsExporting(true);
      await exportInstance();
      onClose();
    } catch (error) {
      console.error("Export failed:", error);
    } finally {
      setIsExporting(false);
    }
  };

  return (
    <BaseModal isOpen={isOpen} onClose={onClose} disableClose={isExporting}>
      <div className="p-6 md:p-8">
        <ModalIcon icon={Download} variant="default" />

        <h2 className="text-2xl font-semibold text-white text-center mb-3">
          Export Instance
        </h2>

        <p className="text-sm text-muted-foreground text-center mb-6">
          Download a complete backup of your instance including all projects,
          tracks, and settings.
        </p>

        {estimatedSizeGB !== undefined && (
          <p className="text-xs text-muted-foreground text-center mb-6">
            Estimated size:{" "}
            <span className="text-white font-medium">
              {estimatedSizeGB.toFixed(1)} GB
            </span>
          </p>
        )}

        <div className="flex flex-col gap-3">
          <Button
            onClick={handleExport}
            disabled={isExporting}
            className="w-full bg-[#0099bb] hover:bg-[#007a94] text-white font-medium"
          >
            {isExporting ? "Exporting..." : "Export"}
          </Button>
          <Button onClick={onClose} disabled={isExporting} className="w-full">
            Cancel
          </Button>
        </div>
      </div>
    </BaseModal>
  );
}
