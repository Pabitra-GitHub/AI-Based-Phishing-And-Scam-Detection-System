import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { ArrowLeft, Trash2, Shield, Calendar, Layers, ExternalLink } from 'lucide-react';
import { scanApi } from '../services/api';
import { ScanResult } from '../types';
import { ScanResultCard } from '../components/security/ScanResultCard';
import { Loader } from '../components/common/Loader';
import { Button } from '../components/common/Button';
import { Modal } from '../components/common/Modal';
import { useToast } from '../context/ToastContext';

export const ScanDetailPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { addToast } = useToast();
  const [scan, setScan] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [deleteModalOpen, setDeleteModalOpen] = useState<boolean>(false);
  const [isDeleting, setIsDeleting] = useState<boolean>(false);

  useEffect(() => {
    const fetchScanDetail = async () => {
      if (!id) return;
      try {
        setLoading(true);
        const data = await scanApi.getScanById(id);
        setScan(data);
      } catch (err: any) {
        addToast('error', 'Failed to load scan', err.response?.data?.detail || 'Scan record not found.');
        navigate('/scan');
      } finally {
        setLoading(false);
      }
    };

    fetchScanDetail();
  }, [id, navigate, addToast]);

  const handleDelete = async () => {
    if (!id) return;
    setIsDeleting(true);
    try {
      await scanApi.deleteScan(id);
      addToast('success', 'Scan Deleted', 'The scan record has been removed.');
      navigate('/scan');
    } catch (err: any) {
      addToast('error', 'Delete Failed', err.response?.data?.detail || 'Could not delete scan.');
    } finally {
      setIsDeleting(false);
      setDeleteModalOpen(false);
    }
  };

  if (loading) {
    return (
      <div className="w-full px-4 sm:px-6 lg:px-8 py-16">
        <Loader message="Loading deep inspection parameters..." />
      </div>
    );
  }

  if (!scan) return null;

  return (
    <div className="w-full px-4 sm:px-6 lg:px-8 py-6 sm:py-8 space-y-8">
      {/* Top Bar Navigation */}
      <div className="flex items-center justify-between">
        <Button
          variant="secondary"
          size="sm"
          onClick={() => navigate('/scan')}
          leftIcon={<ArrowLeft className="w-4 h-4" />}
        >
          Back to Scanner
        </Button>
      </div>

      {/* Main Scan Assessment Card */}
      <div>
        <h1 className="text-2xl font-extrabold text-slate-900 mb-4 flex items-center gap-2">
          <Shield className="w-6 h-6 text-blue-600" />
          Detailed Inspection Report
        </h1>
        <ScanResultCard result={scan} showDeepLink={false} />
      </div>

      {/* Delete Confirmation Modal */}
      <Modal
        isOpen={deleteModalOpen}
        onClose={() => setDeleteModalOpen(false)}
        title="Confirm Scan Deletion"
        maxWidth="sm"
      >
        <div className="space-y-4">
          <p className="text-xs text-slate-600 leading-relaxed">
            Are you sure you want to delete this scan record for{' '}
            <span className="font-mono font-bold text-slate-900">{scan.input_value}</span>? This action cannot be undone.
          </p>
          <div className="flex justify-end space-x-2 pt-2">
            <Button
              variant="secondary"
              size="sm"
              onClick={() => setDeleteModalOpen(false)}
              disabled={isDeleting}
            >
              Cancel
            </Button>
            <Button
              variant="danger"
              size="sm"
              onClick={handleDelete}
              isLoading={isDeleting}
            >
              Delete
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  );
};
