import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { all_routes } from "../../router/all_routes";
// import { pipelineData } from '../../../core/data/json/pipelineData'; // Commented out static data
import CollapseHeader from "../../../core/common/collapse-header/collapse-header";
import PredefinedDateRanges from "../../../core/common/datePicker";
import Table from "../../../core/common/dataTable/index";
import CrmsModal from "../../../core/modals/crms_modal";
import { useSocket } from "../../../SocketContext";
import { Socket } from "socket.io-client";
import EditPipeline from "../../../core/modals/edit_pipeline";
import DeletePipeline from "../../../core/modals/delete_pipeline";
import { message } from "antd";
import AddPipeline from "../../../core/modals/add_pipeline";

const DEAL_VALUE_RANGES = [
  { label: "$0 - $1,000", value: [0, 1000] },
  { label: "$1,000 - $5,000", value: [1000, 5000] },
  { label: "$5,000 - $10,000", value: [5000, 10000] },
  { label: "$10,000+", value: [10000, Infinity] },
];
const SORT_OPTIONS = [
  { label: "Last 7 Days", value: "last7days" },
  { label: "Recently Added", value: "recent" },
  { label: "Ascending", value: "asc" },
  { label: "Descending", value: "desc" },
];

const Pipeline = () => {
  const routes = all_routes;
  // const data = pipelineData; // Commented out static data
  const [pipelines, setPipelines] = useState<any[]>([]);
  const [filteredPipelines, setFilteredPipelines] = useState<any[]>([]);
  const [availableStages, setAvailableStages] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const socket = useSocket() as Socket | null;
  const [editPipeline, setEditPipeline] = useState<any | null>(null);
  const [deletePipeline, setDeletePipeline] = useState<any | null>(null);
  const [exporting, setExporting] = useState(false);

  const [filters, setFilters] = useState<{
    dateRange: { start: string; end: string } | null;
    stage: string;
    status: string;
    dealValue: string;
    sort: string;
  }>({
    dateRange: null,
    stage: "",
    status: "",
    dealValue: "",
    sort: "",
  });

  const handleFilterChange = (field: string, value: any) => {
    setFilters((prev) => ({ ...prev, [field]: value }));
  };

  const handleClearFilters = () => {
    console.log("[Pipeline] Clearing filters");
    const clearedFilters = {
      dateRange: null,
      stage: "",
      status: "",
      dealValue: "",
      sort: "",
    };
    setFilters(clearedFilters);
  };

  const fetchPipelines = () => {
    if (!socket) return;
    setLoading(true);
    setError(null);

    console.log("[Pipeline] Fetching all pipelines from backend");
    socket.emit("pipeline:getAll", {});
  };

  const fetchStages = () => {
    if (!socket) return;
    console.log("[Pipeline] Fetching stages from backend");
    socket.emit("stage:getAll");
  };

  const updateAvailableStages = (pipelinesData: any[]) => {
    // Get unique stages from pipelines
    const pipelineStages = Array.from(
      new Set(pipelinesData.map((p) => p.stage).filter(Boolean))
    );
    console.log("[Pipeline] Unique stages from pipelines:", pipelineStages);

    // Set pipeline stages as initial available stages
    // Custom stages will be added by the stages handler
    setAvailableStages(pipelineStages);
  };

  useEffect(() => {
    if (!socket) return;
    fetchPipelines();
    fetchStages(); // Also fetch stages

    const pipelineHandler = (res: any) => {
      console.log("Pipeline getAll response:", res);
      if (res.done) {
        // Log the first pipeline to see the date format
        if (res.data && res.data.length > 0) {
          console.log("Sample pipeline data:", {
            id: res.data[0]._id,
            createdDate: res.data[0].createdDate,
            createdDateType: typeof res.data[0].createdDate,
            createdDateConstructor: res.data[0].createdDate?.constructor?.name,
          });
        }
        setPipelines(res.data || []);
        setFilteredPipelines(res.data || []); // Initialize filtered pipelines with all data
        updateAvailableStages(res.data || []); // Update available stages
        setError(null);
        console.log(`Loaded ${res.data?.length || 0} pipelines`);
      } else {
        setError(res.error || "Failed to fetch pipelines");
        console.error("Failed to fetch pipelines:", res.error);
      }
      setLoading(false);
    };

    const stagesHandler = (res: any) => {
      console.log("Stages getAll response:", res);
      if (res.done && res.data) {
        const customStages = res.data.map((stage: any) => stage.name);
        console.log("Custom stages from backend:", customStages);

        // Combine with existing pipeline stages
        setAvailableStages((prev) => {
          const combined = Array.from(new Set([...prev, ...customStages]));
          console.log("Combined available stages:", combined);
          return combined;
        });
      }
    };

    socket.on("pipeline:getAll-response", pipelineHandler);
    socket.on("stage:getAll-response", stagesHandler);

    return () => {
      socket.off("pipeline:getAll-response", pipelineHandler);
      socket.off("stage:getAll-response", stagesHandler);
    };
  }, [socket]);

  // Frontend filtering logic - similar to packages and companies modules
  useEffect(() => {
    if (pipelines && filters) {
      console.log("[Pipeline] Applying frontend filters:", filters);
      console.log(
        "[Pipeline] Total pipelines before filtering:",
        pipelines.length
      );

      let result = [...pipelines]; // Always start from the original pipelines

      // Stage filter
      if (filters.stage) {
        result = result.filter((pipeline) => pipeline.stage === filters.stage);
      }

      // Status filter
      if (filters.status) {
        result = result.filter(
          (pipeline) => pipeline.status === filters.status
        );
      }

      // Deal value filter
      if (filters.dealValue) {
        const ranges: Record<string, [number, number]> = {
          "$0 - $1,000": [0, 1000],
          "$1,000 - $5,000": [1000, 5000],
          "$5,000 - $10,000": [5000, 10000],
          "$10,000+": [10000, Infinity],
        };
        const range = ranges[filters.dealValue];
        if (range) {
          result = result.filter((pipeline) => {
            const value = pipeline.totalDealValue || 0;
            return (
              value >= range[0] &&
              (range[1] === Infinity ? true : value <= range[1])
            );
          });
        }
      }

      // Date range filter
      if (filters.dateRange?.start || filters.dateRange?.end) {
        result = result.filter((pipeline) => {
          if (!pipeline.createdDate) return false;

          const pipelineDate = new Date(pipeline.createdDate);
          if (isNaN(pipelineDate.getTime())) return false;

          let start = filters.dateRange?.start
            ? new Date(filters.dateRange.start)
            : null;
          let end = filters.dateRange?.end
            ? new Date(filters.dateRange.end)
            : null;

          // Check if this is "All Time" (very old start date)
          const allTimeStart = new Date("1970-01-01T00:00:00.000Z");
          if (start && start.getTime() === allTimeStart.getTime()) {
            start = null; // Don't filter by start date for "All Time"
          }

          if (start) start.setHours(0, 0, 0, 0);
          if (end) end.setHours(23, 59, 59, 999);

          return (
            (!start || pipelineDate >= start) && (!end || pipelineDate <= end)
          );
        });
      }

      // Sort
      if (filters.sort) {
        result.sort((a, b) => {
          const dateA = new Date(a.createdDate);
          const dateB = new Date(b.createdDate);

          switch (filters.sort) {
            case "asc":
              return dateA.getTime() - dateB.getTime();
            case "desc":
              return dateB.getTime() - dateA.getTime();
            case "recent":
              return dateB.getTime() - dateA.getTime();
            case "last7days":
              // For last 7 days, still sort by date descending
              return dateB.getTime() - dateA.getTime();
            default:
              return 0;
          }
        });
      }

      console.log("[Pipeline] Filtered pipelines count:", result.length);
      setFilteredPipelines(result);
    }
  }, [filters, pipelines]);

  // Listen for global refresh events
  useEffect(() => {
    const handleRefreshPipelines = () => {
      console.log("Global refresh event received, fetching pipelines...");
      fetchPipelines();
      fetchStages(); // Also refresh stages
    };

    window.addEventListener("refresh-pipelines", handleRefreshPipelines);

    return () => {
      window.removeEventListener("refresh-pipelines", handleRefreshPipelines);
    };
  }, []);

  // Handle edit click
  const handleEditClick = (pipeline: any) => {
    console.log("Edit pipeline clicked:", pipeline);
    setEditPipeline(pipeline);
    // Open the modal
    const modal = document.getElementById("edit-pipeline-modal");
    if (modal) {
      const bootstrapModal = new (window as any).bootstrap.Modal(modal);
      bootstrapModal.show();
    }
  };

  // Handle delete click
  const handleDeleteClick = (pipeline: any) => {
    console.log("Delete pipeline clicked:", pipeline);
    setDeletePipeline(pipeline);
    // Open the modal
    const modal = document.getElementById("delete-pipeline-modal");
    if (modal) {
      const bootstrapModal = new (window as any).bootstrap.Modal(modal);
      bootstrapModal.show();
    }
  };

  // Handle pipeline updated
  const handlePipelineUpdated = () => {
    console.log("Pipeline updated, refreshing list...");
    fetchPipelines();
    // Also dispatch global event for other components
    window.dispatchEvent(new Event("refresh-pipelines"));
  };

  // Handle pipeline deleted
  const handlePipelineDeleted = () => {
    console.log("Pipeline deleted, refreshing list...");
    fetchPipelines();
    // Also dispatch global event for other components
    window.dispatchEvent(new Event("refresh-pipelines"));
  };

  // Export functions
  const handleExportPDF = async () => {
    if (!socket) {
      message.error("Socket connection not available");
      return;
    }

    setExporting(true);
    try {
      console.log("Starting PDF export...");

      // Emit socket event to generate PDF
      socket.emit("pipeline/export-pdf");

      // Listen for response
      const handlePDFResponse = (response: any) => {
        if (response.done) {
          console.log("PDF generated successfully:", response.data.pdfUrl);

          // Create a temporary link and trigger download
          const link = document.createElement("a");
          link.href = response.data.pdfUrl;
          link.download = `pipelines_${Date.now()}.pdf`;
          document.body.appendChild(link);
          link.click();
          document.body.removeChild(link);

          message.success("PDF exported successfully!");
        } else {
          console.error("PDF export failed:", response.error);
          message.error(`PDF export failed: ${response.error}`);
        }
        setExporting(false);
        socket.off("pipeline/export-pdf-response", handlePDFResponse);
      };

      socket.on("pipeline/export-pdf-response", handlePDFResponse);
    } catch (error) {
      console.error("Error exporting PDF:", error);
      message.error("Failed to export PDF");
      setExporting(false);
    }
  };

  const handleExportExcel = async () => {
    if (!socket) {
      message.error("Socket connection not available");
      return;
    }

    setExporting(true);
    try {
      console.log("Starting Excel export...");

      // Emit socket event to generate Excel
      socket.emit("pipeline/export-excel");

      // Listen for response
      const handleExcelResponse = (response: any) => {
        if (response.done) {
          console.log("Excel generated successfully:", response.data.excelUrl);

          // Create a temporary link and trigger download
          const link = document.createElement("a");
          link.href = response.data.excelUrl;
          link.download = `pipelines_${Date.now()}.xlsx`;
          document.body.appendChild(link);
          link.click();
          document.body.removeChild(link);

          message.success("Excel exported successfully!");
        } else {
          console.error("Excel export failed:", response.error);
          message.error(`Excel export failed: ${response.error}`);
        }
        setExporting(false);
        socket.off("pipeline/export-excel-response", handleExcelResponse);
      };

      socket.on("pipeline/export-excel-response", handleExcelResponse);
    } catch (error) {
      console.error("Error exporting Excel:", error);
      message.error("Failed to export Excel");
      setExporting(false);
    }
  };

  // Map backend fields to frontend columns if needed
  const columns = [
    {
      title: "Pipeline Name",
      dataIndex: "pipelineName",
      render: (text: string, record: any) => (
        <h6 className="fs-14 fw-medium">{text}</h6>
      ),
      sorter: (a: any, b: any) => a.pipelineName.length - b.pipelineName.length,
    },
    {
      title: "Total Deal Value",
      dataIndex: "totalDealValue",
      render: (value: number) => `$${value.toLocaleString()}`,
      sorter: (a: any, b: any) => a.totalDealValue - b.totalDealValue,
    },
    {
      title: "No of Deals",
      dataIndex: "noOfDeals",
      sorter: (a: any, b: any) => a.noOfDeals - b.noOfDeals,
    },
    {
      title: "Stages",
      dataIndex: "stage",
      render: (text: string) => (
        <div className=" d-flex align-items-center">
          <div
            className="progress me-2"
            role="progressbar"
            aria-label="Basic example"
            aria-valuenow={0}
            aria-valuemin={0}
            aria-valuemax={100}
            style={{ height: 5, minWidth: 80 }}
          >
            <div
              className={`progress-bar  ${
                text === "Won"
                  ? "bg-success"
                  : text === "In Pipeline"
                  ? "bg-purple"
                  : text === "Conversation"
                  ? "bg-skyblue"
                  : text === "Follow Up"
                  ? "bg-warning"
                  : text === "Schedule servise"
                  ? "bg-pink"
                  : "bg-danger"
              }`}
              style={{ width: "100%" }}
            />
          </div>
          <span className="fs-14 fw-normal">{text}</span>
        </div>
      ),
      sorter: (a: any, b: any) => a.stage.length - b.stage.length,
    },
    {
      title: "Created Date",
      dataIndex: "createdDate",
      render: (date: any) => {
        try {
          if (!date) return "N/A";
          const dateObj = date instanceof Date ? date : new Date(date);
          if (isNaN(dateObj.getTime())) return "N/A";
          return dateObj.toLocaleDateString();
        } catch (error) {
          console.error("Error formatting date:", error, "date value:", date);
          return "N/A";
        }
      },
      sorter: (a: any, b: any) => {
        try {
          const dateA =
            a.createdDate instanceof Date
              ? a.createdDate
              : new Date(a.createdDate);
          const dateB =
            b.createdDate instanceof Date
              ? b.createdDate
              : new Date(b.createdDate);
          if (isNaN(dateA.getTime()) || isNaN(dateB.getTime())) return 0;
          return dateA.getTime() - dateB.getTime();
        } catch (error) {
          return 0;
        }
      },
    },
    {
      title: "Status",
      dataIndex: "status",
      render: (text: string) => (
        <>
          <span
            className={`badge d-inline-flex align-items-center badge-xs ${
              text === "Active" ? "badge-success" : "badge-danger"
            }`}
          >
            <i className="ti ti-point-filled me-1"></i>
            {text}
          </span>
        </>
      ),
      sorter: (a: any, b: any) => a.status.length - b.status.length,
    },
    {
      title: "",
      dataIndex: "actions",
      render: (_: any, record: any) => (
        <div className="action-icon d-inline-flex">
          <Link
            to="#"
            className="me-2"
            data-bs-toggle="modal"
            data-bs-target="#edit_pipeline"
            onClick={(e) => {
              e.preventDefault();
              handleEditClick(record);
            }}
          >
            <i className="ti ti-edit" />
          </Link>
          <Link
            to="#"
            data-bs-toggle="modal"
            data-bs-target="#delete_pipeline"
            onClick={(e) => {
              e.preventDefault();
              handleDeleteClick(record);
            }}
          >
            <i className="ti ti-trash" />
          </Link>
        </div>
      ),
    },
  ];

  return (
    <>
      {/* Page Wrapper */}
      <div className="page-wrapper">
        <div className="content">
          {/* Breadcrumb */}
          <div className="d-md-flex d-block align-items-center justify-content-between page-breadcrumb mb-3">
            <div className="my-auto mb-2">
              <h2 className="mb-1">Pipeline</h2>
              <nav>
                <ol className="breadcrumb mb-0">
                  <li className="breadcrumb-item">
                    <Link to={routes.adminDashboard}>
                      <i className="ti ti-smart-home" />
                    </Link>
                  </li>
                  <li className="breadcrumb-item">CRM</li>
                  <li className="breadcrumb-item active" aria-current="page">
                    Pipeline List
                  </li>
                </ol>
              </nav>
            </div>
            <div className="col-auto float-end ms-auto">
              <div className="d-flex my-xl-auto right-content align-items-center flex-wrap">
                {/* Export Dropdown */}
                <div className="me-2 mb-2">
                  <div className="dropdown">
                    <Link
                      to="#"
                      className="dropdown-toggle btn btn-white d-inline-flex align-items-center"
                      data-bs-toggle="dropdown"
                      onClick={(e) => e.preventDefault()}
                    >
                      <i className="ti ti-file-export me-1" />
                      {exporting ? "Exporting..." : "Export"}
                    </Link>
                    <ul className="dropdown-menu dropdown-menu-end p-3">
                      <li>
                        <Link
                          to="#"
                          className="dropdown-item rounded-1"
                          onClick={(e) => {
                            e.preventDefault();
                            handleExportPDF();
                          }}
                        >
                          <i className="ti ti-file-type-pdf me-1" />
                          Export as PDF
                        </Link>
                      </li>
                      <li>
                        <Link
                          to="#"
                          className="dropdown-item rounded-1"
                          onClick={(e) => {
                            e.preventDefault();
                            handleExportExcel();
                          }}
                        >
                          <i className="ti ti-file-type-xls me-1" />
                          Export as Excel
                        </Link>
                      </li>
                    </ul>
                  </div>
                </div>

                {/* Add Pipeline Button */}
                <div className="mb-2">
                  <Link
                    to="#"
                    data-bs-toggle="modal"
                    data-bs-target="#add_pipeline"
                    className="btn btn-primary d-flex align-items-center"
                  >
                    <i className="ti ti-circle-plus me-2" />
                    Add Pipeline
                  </Link>
                </div>
              </div>
            </div>
          </div>
          {/* /Breadcrumb */}
          {/* Leads List */}
          <div className="card">
            <div className="card-header d-flex align-items-center justify-content-between flex-wrap row-gap-3">
              <h5>Pipeline List</h5>
              <div className="d-flex my-xl-auto right-content align-items-center flex-wrap row-gap-3">
                {/* Date Range Filter */}
                <div className="me-3">
                  <div className="input-icon-end position-relative">
                    <PredefinedDateRanges
                      value={filters.dateRange || undefined}
                      onChange={(range) => {
                        console.log("[Pipeline] Date range changed:", range);
                        handleFilterChange("dateRange", range);
                      }}
                    />
                    <span className="input-icon-addon">
                      <i className="ti ti-chevron-down" />
                    </span>
                  </div>
                </div>

                {/* Stage Filter */}
                <div className="dropdown me-3">
                  <select
                    className="form-select"
                    value={filters.stage}
                    onChange={(e) =>
                      handleFilterChange("stage", e.target.value)
                    }
                  >
                    <option value="">All Stages</option>
                    {availableStages.map((stage) => (
                      <option key={stage} value={stage}>
                        {stage}
                      </option>
                    ))}
                  </select>
                </div>

                {/* Status Filter */}
                <div className="dropdown me-3">
                  <select
                    className="form-select"
                    value={filters.status}
                    onChange={(e) =>
                      handleFilterChange("status", e.target.value)
                    }
                  >
                    <option value="">All Statuses</option>
                    <option value="Active">Active</option>
                    <option value="Inactive">Inactive</option>
                  </select>
                </div>

                {/* Deal Value Range Filter */}
                <div className="dropdown me-3">
                  <select
                    className="form-select"
                    value={filters.dealValue}
                    onChange={(e) =>
                      handleFilterChange("dealValue", e.target.value)
                    }
                  >
                    <option value="">All Deal Values</option>
                    {DEAL_VALUE_RANGES.map((range) => (
                      <option key={range.label} value={range.label}>
                        {range.label}
                      </option>
                    ))}
                  </select>
                </div>

                {/* Sort Options */}
                <div className="dropdown me-3">
                  <select
                    className="form-select"
                    value={filters.sort}
                    onChange={(e) => handleFilterChange("sort", e.target.value)}
                  >
                    <option value="">Sort By</option>
                    {SORT_OPTIONS.map((opt) => (
                      <option key={opt.value} value={opt.value}>
                        {opt.label}
                      </option>
                    ))}
                  </select>
                </div>
                {/* Clear Filters Button */}
                <button
                  className="btn btn-light ms-2"
                  onClick={handleClearFilters}
                >
                  Clear Filters
                </button>
              </div>
            </div>
            <div className="card-body p-0">
              {loading ? (
                <div className="p-4 text-center">Loading pipelines...</div>
              ) : error ? (
                <div className="p-4 text-danger text-center">{error}</div>
              ) : (
                <>
                  {/* Filter Summary */}
                  <Table
                    dataSource={filteredPipelines}
                    columns={columns}
                    Selection={true}
                  />
                </>
              )}
            </div>
          </div>
          {/* /Leads List */}
        </div>
        <div className="footer d-sm-flex align-items-center justify-content-between border-top bg-white p-3">
          <p className="mb-0">2014 - 2025 © Amasqis.</p>
          <p>
            Designed &amp; Developed By{" "}
            <Link to="https://amasqis.ai" className="text-primary">
              Amasqis
            </Link>
          </p>
        </div>
      </div>
      {/* /Page Wrapper */}
      <CrmsModal />
      <AddPipeline />
      <EditPipeline
        pipeline={editPipeline}
        onPipelineUpdated={handlePipelineUpdated}
      />
      <DeletePipeline
        pipeline={deletePipeline}
        onPipelineDeleted={handlePipelineDeleted}
      />
    </>
  );
};

export default Pipeline;
