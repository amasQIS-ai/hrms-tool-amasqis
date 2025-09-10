import React, { useEffect, useState, useRef } from "react";
import { Link } from "react-router-dom";
import { all_routes } from "../../router/all_routes";
import CollapseHeader from "../../../core/common/collapse-header/collapse-header";
import ImageWithBasePath from "../../../core/common/imageWithBasePath";
import ReactApexChart from "react-apexcharts";
import Table from "../../../core/common/dataTable/index";
import { useSocket } from "../../../SocketContext";
import { Socket } from "socket.io-client";
import { ApexOptions } from "apexcharts";
import { message } from "antd";

// Helper to format date as dd-mm-yyyy
const formatDate = (iso: string) => {
  const d = new Date(iso);
  return d.toLocaleDateString("en-GB"); // dd/mm/yyyy
};

const Subscription = () => {
  const [statusFilter, setStatusFilter] = useState<string>("All");
  const [planFilter, setPlanFilter] = useState<string>("All");
  const socket = useSocket() as Socket | null;
  const [stats, setStats] = useState({
    totalTransaction: 0,
    totalSubscribers: 0,
    activeSubscribers: 0,
    expiredSubscribers: 0,
  });
  const [data, setData] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  const [selectedInvoice, setSelectedInvoice] = useState<any>(null);
  const invoiceRef = useRef<HTMLDivElement>(null);

  // Helper to get invoice number from company id
  const getInvoiceNumber = (companyId: string) => {
    return companyId?.slice(-4).toUpperCase() || "0000";
  };

  // Fetch stats
  useEffect(() => {
    if (!socket) return;

    socket.emit("superadmin/subscriptions/fetch-stats");
    socket.on("superadmin/subscriptions/fetch-stats-response", (res) => {
      if (res.done) {
        setStats({
          totalTransaction: res.data.totalTransaction || 0,
          totalSubscribers: res.data.totalSubscribers || 0,
          activeSubscribers: res.data.activeSubscribers || 0,
          expiredSubscribers: res.data.expiredSubscribers || 0,
        });
      }
    });
    return () => {
      socket.off("superadmin/subscriptions/fetch-stats-response");
    };
  }, [socket]);

  // Fetch subscription list
  useEffect(() => {
    if (!socket) return;

    setLoading(true);
    socket.emit("superadmin/subscriptions/fetch-list");
    socket.on("superadmin/subscriptions/fetch-list-response", (res) => {
      if (res.done) {
        setData(res.data || []);
      }
      setLoading(false);
    });
    return () => {
      socket.off("superadmin/subscriptions/fetch-list-response");
    };
  }, [socket]);

  const handleInvoiceClick = (record: any) => {
    setSelectedInvoice(record);
  };

  const handleDownloadPDF = async () => {
    if (!selectedInvoice) {
      message.error("Please select an invoice first");
      return;
    }

    if (!socket) {
      message.error("Socket connection not available");
      return;
    }

    try {
      console.log("Starting PDF download process...");
      console.log("Selected invoice data:", selectedInvoice);

      // Ensure we have the required IDs
      if (!selectedInvoice.companyId) {
        throw new Error("Company ID is missing");
      }
      if (!selectedInvoice.planId) {
        // Try to extract planId from the Plan field if it's in the format "Plan Name (Plan Type)"
        const planMatch = selectedInvoice.Plan?.match(/\(([^)]+)\)/);
        if (!planMatch) {
          throw new Error(
            "Plan ID is missing and could not be determined from plan name"
          );
        }
        // Use the plan type as a fallback
        selectedInvoice.planId = planMatch[1];
      }

      const invoiceData = {
        invoiceId: selectedInvoice._id,
        companyId: selectedInvoice.companyId,
        planId: selectedInvoice.planId,
      };

      console.log("Emitting download-invoice event with data:", invoiceData);

      // Emit socket event to generate PDF
      socket.emit("superadmin/subscriptions/download-invoice", invoiceData);

      // Listen for the response
      socket.once(
        "superadmin/subscriptions/download-invoice-response",
        (response) => {
          console.log("Received PDF generation response:", response);

          if (response.done && response.data?.pdfUrl) {
            // Create a temporary link and trigger download
            const link = document.createElement("a");
            link.href = response.data.pdfUrl;
            link.download = `invoice_${
              selectedInvoice.companyId
            }_${Date.now()}.pdf`;
            link.id = "pdf-download-link";
            link.setAttribute("type", "application/pdf");
            link.setAttribute("target", "_blank");
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            message.success("Invoice downloaded successfully");
          } else {
            message.error(response.error || "Failed to generate PDF");
          }
        }
      );
    } catch (error: any) {
      console.error("Error downloading PDF:", error);
      message.error(error.message || "Failed to download PDF");
    }
  };

  //  const data = subscription_details;
  const columns = [
    {
      title: "Company Name",
      dataIndex: "CompanyName",
      render: (text: String, record: any) => (
        <div className="d-flex align-items-center file-name-icon">
          <Link to="#" className="avatar avatar-md border rounded-circle">
            <img
              src={record.Image}
              className="img-fluid rounded-circle"
              alt={record.CompanyName}
              style={{ width: "40px", height: "40px", objectFit: "cover" }}
              onError={(e) => {
                e.currentTarget.src = "/assets/img/company/company-default.svg";
              }}
            />
          </Link>
          <div className="ms-2">
            <h6 className="fw-medium">
              <Link to="#">{record.CompanyName}</Link>
            </h6>
            <span className="text-muted fs-12">{record.CompanyEmail}</span>
          </div>
        </div>
      ),
      sorter: (a: any, b: any) => a.CompanyName.length - b.CompanyName.length,
    },
    {
      title: "Plan",
      dataIndex: "Plan",
      sorter: (a: any, b: any) => a.Plan.length - b.Plan.length,
    },
    {
      title: "Billing Cycle",
      dataIndex: "BillCycle",
      render: (text: number) => <span>{text} Days</span>,
      sorter: (a: any, b: any) => a.BillCycle - b.BillCycle,
    },
    {
      title: "Amount",
      dataIndex: "Amount",
      render: (text: number) => <span>${text ? text.toFixed(2) : "0.00"}</span>,
      sorter: (a: any, b: any) => (a.Amount || 0) - (b.Amount || 0),
    },
    {
      title: "Created Date",
      dataIndex: "CreatedDate",
      render: (iso: string) => <span>{formatDate(iso)}</span>,
      sorter: (a: any, b: any) =>
        new Date(a.CreatedDate).getTime() - new Date(b.CreatedDate).getTime(),
    },
    {
      title: "Expired On",
      dataIndex: "ExpiringDate",
      render: (iso: string) => <span>{formatDate(iso)}</span>,
      sorter: (a: any, b: any) =>
        new Date(a.ExpiringDate).getTime() - new Date(b.ExpiringDate).getTime(),
    },
    {
      title: "Status",
      dataIndex: "Status",
      render: (text: string) => (
        <span
          className={`badge ${
            text === "Paid"
              ? "badge-success"
              : text === "Expired"
              ? "badge-danger"
              : "badge-secondary"
          } d-inline-flex align-items-center badge-xs`}
        >
          <i className="ti ti-point-filled me-1" />
          {text}
        </span>
      ),
      sorter: (a: any, b: any) => a.Status.length - b.Status.length,
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
            data-bs-target="#view_invoice"
            onClick={() => handleInvoiceClick(record)}
          >
            <i className="ti ti-file-invoice" />
          </Link>
          <Link to="#" data-bs-toggle="modal" data-bs-target="#delete_modal">
            <i className="ti ti-trash" />
          </Link>
        </div>
      ),
    },
  ];

  // Filter data based on status and plan
  const filteredData = data.filter((item) => {
    const statusMatch = statusFilter === "All" || item.Status === statusFilter;
    const planMatch = planFilter === "All" || item.Plan === planFilter;
    return statusMatch && planMatch;
  });

  // Get unique plans for filter dropdown
  const planOptions = Array.from(new Set(data.map((item) => item.Plan)));

  // Chart options for stats with different colors
  const getChartOptions = (color: string): ApexOptions => ({
    series: [
      {
        name: "",
        data: [6, 2, 8, 4, 3, 8, 1, 3, 6, 5, 9, 2, 8, 1, 4, 8, 9, 8, 2, 1],
      },
    ],
    fill: {
      type: "solid",
      opacity: 1,
    },
    chart: {
      foreColor: "#fff",
      type: "area",
      width: 80,
      toolbar: {
        show: false,
      },
      zoom: {
        enabled: false,
      },
      dropShadow: {
        enabled: false,
        top: 3,
        left: 14,
        blur: 4,
        opacity: 0.12,
        color: "#fff",
      },
      sparkline: {
        enabled: true,
      },
    },
    markers: {
      size: 0,
      colors: [color],
      strokeColors: "#fff",
      strokeWidth: 0,
      hover: {
        size: 7,
      },
    },
    plotOptions: {
      bar: {
        horizontal: false,
        columnWidth: "35%",
        borderRadius: 4,
        distributed: false,
        dataLabels: {
          position: "top",
        },
      },
    },
    dataLabels: {
      enabled: false,
    },
    stroke: {
      width: 0,
      curve: "monotoneCubic",
    },
    colors: [color],
    xaxis: {
      categories: [
        "Jan",
        "Feb",
        "Mar",
        "Apr",
        "May",
        "Jun",
        "Jul",
        "Aug",
        "Sep",
        "Oct",
        "Nov",
        "Dec",
      ],
    },
    tooltip: {
      theme: "dark",
      fixed: {
        enabled: false,
      },
      x: {
        show: false,
      },
      marker: {
        show: false,
      },
    },
  });

  return (
    <>
      {/* Page Wrapper */}
      <div className="page-wrapper">
        <div className="content">
          {/* Breadcrumb */}
          <div className="d-md-flex d-block align-items-center justify-content-between page-breadcrumb mb-3">
            <div className="my-auto mb-2">
              <h2 className="mb-1">Subscription</h2>
              <nav>
                <ol className="breadcrumb mb-0">
                  <li className="breadcrumb-item">
                    <Link to={all_routes.adminDashboard}>
                      <i className="ti ti-smart-home" />
                    </Link>
                  </li>
                  <li className="breadcrumb-item">Superadmin</li>
                  <li className="breadcrumb-item active" aria-current="page">
                    Subscription
                  </li>
                </ol>
              </nav>
            </div>
            <div className="d-flex my-xl-auto right-content align-items-center flex-wrap ">
              <div className="me-2 mb-2">
                <div className="dropdown">
                  <Link
                    to="#"
                    className="dropdown-toggle btn btn-white d-inline-flex align-items-center"
                    data-bs-toggle="dropdown"
                  >
                    <i className="ti ti-file-export me-1" />
                    Export
                  </Link>
                  <ul className="dropdown-menu  dropdown-menu-end p-3">
                    <li>
                      <Link to="#" className="dropdown-item rounded-1">
                        <i className="ti ti-file-type-pdf me-1" />
                        Export as PDF
                      </Link>
                    </li>
                    <li>
                      <Link to="#" className="dropdown-item rounded-1">
                        <i className="ti ti-file-type-xls me-1" />
                        Export as Excel{" "}
                      </Link>
                    </li>
                  </ul>
                </div>
              </div>
              <div className="head-icons">
                <CollapseHeader />
              </div>
            </div>
          </div>
          {/* /Breadcrumb */}
          <div className="row">
            <div className="col-xl-3 col-md-6 d-flex">
              <div className="card flex-fill">
                <div className="card-body">
                  <div className="border-bottom pb-3 mb-3">
                    <div className="row align-items-center">
                      <div className="col-7">
                        <div>
                          <span className="fs-14 fw-normal text-truncate mb-1">
                            Total Transaction
                          </span>
                          <h5>${stats.totalTransaction.toFixed(2)}</h5>
                        </div>
                      </div>
                      <div className="col-5">
                        <ReactApexChart
                          options={getChartOptions("#F7A37A")}
                          series={getChartOptions("#F7A37A").series}
                          type="area"
                          width={60}
                          height={35}
                        />
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
            <div className="col-xl-3 col-md-6 d-flex">
              <div className="card flex-fill">
                <div className="card-body">
                  <div className="border-bottom pb-3 mb-3">
                    <div className="row align-items-center">
                      <div className="col-7">
                        <div>
                          <span className="fs-14 fw-normal text-truncate mb-1">
                            Total Subscribers
                          </span>
                          <h5>{stats.totalSubscribers}</h5>
                        </div>
                      </div>
                      <div className="col-5">
                        <ReactApexChart
                          options={getChartOptions("#4CAF50")}
                          series={getChartOptions("#4CAF50").series}
                          type="area"
                          width={60}
                          height={35}
                        />
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
            <div className="col-xl-3 col-md-6 d-flex">
              <div className="card flex-fill">
                <div className="card-body">
                  <div className="border-bottom pb-3 mb-3">
                    <div className="row align-items-center">
                      <div className="col-7">
                        <div>
                          <span className="fs-14 fw-normal text-truncate mb-1">
                            Active Subscribers
                          </span>
                          <h5>{stats.activeSubscribers}</h5>
                        </div>
                      </div>
                      <div className="col-5">
                        <ReactApexChart
                          options={getChartOptions("#2196F3")}
                          series={getChartOptions("#2196F3").series}
                          type="area"
                          width={60}
                          height={35}
                        />
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
            <div className="col-xl-3 col-md-6 d-flex">
              <div className="card flex-fill">
                <div className="card-body">
                  <div className="border-bottom pb-3 mb-3">
                    <div className="row align-items-center">
                      <div className="col-7">
                        <div>
                          <span className="fs-14 fw-normal text-truncate mb-1">
                            Expired Subscribers
                          </span>
                          <h5>{stats.expiredSubscribers}</h5>
                        </div>
                      </div>
                      <div className="col-5">
                        <ReactApexChart
                          options={getChartOptions("#F44336")}
                          series={getChartOptions("#F44336").series}
                          type="area"
                          width={60}
                          height={35}
                        />
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
          <div className="card">
            <div className="card-header d-flex align-items-center justify-content-between flex-wrap row-gap-3">
              <h5>Subscription List</h5>
              <div className="d-flex my-xl-auto right-content align-items-center flex-wrap row-gap-3">
                <div className="dropdown me-3">
                  <button
                    className="dropdown-toggle btn btn-white d-inline-flex align-items-center"
                    data-bs-toggle="dropdown"
                    type="button"
                  >
                    Select Plan
                  </button>
                  <ul className="dropdown-menu dropdown-menu-end p-3">
                    <li>
                      <button
                        className="dropdown-item rounded-1"
                        onClick={() => setPlanFilter("All")}
                      >
                        All
                      </button>
                    </li>
                    {planOptions.map((plan) => (
                      <li key={plan}>
                        <button
                          className="dropdown-item rounded-1"
                          onClick={() => setPlanFilter(plan)}
                        >
                          {plan}
                        </button>
                      </li>
                    ))}
                  </ul>
                </div>
                <div className="dropdown me-3">
                  <button
                    className="dropdown-toggle btn btn-white d-inline-flex align-items-center"
                    data-bs-toggle="dropdown"
                    type="button"
                  >
                    Select Status
                  </button>
                  <ul className="dropdown-menu dropdown-menu-end p-3">
                    <li>
                      <button
                        className="dropdown-item rounded-1"
                        onClick={() => setStatusFilter("All")}
                      >
                        All
                      </button>
                    </li>
                    <li>
                      <button
                        className="dropdown-item rounded-1"
                        onClick={() => setStatusFilter("Paid")}
                      >
                        Paid
                      </button>
                    </li>
                    <li>
                      <button
                        className="dropdown-item rounded-1"
                        onClick={() => setStatusFilter("Expired")}
                      >
                        Expired
                      </button>
                    </li>
                  </ul>
                </div>
              </div>
            </div>
            <div className="card-body p-0">
              <Table
                dataSource={filteredData}
                columns={columns}
                Selection={false}
              />
              <Table
                dataSource={filteredData}
                columns={columns}
                Selection={false}
              />
            </div>
          </div>
        </div>
        <div className="footer d-sm-flex align-items-center justify-content-between border-top bg-white p-3">
          <p className="mb-0">2014 - 2025 © SmartHR.</p>
          <p>
            Designed &amp; Developed By{" "}
            <Link to="amasqis.ai" className="text-primary">
              amasQIS.ai
            </Link>
          </p>
        </div>
      </div>
      {/* /Page Wrapper */}
      {/* View Invoice */}
      <div className="modal fade" id="view_invoice">
        <div className="modal-dialog modal-dialog-centered modal-lg">
          <div className="modal-content">
            <div className="modal-body p-5">
              {selectedInvoice && (
                <div ref={invoiceRef} id="invoice-content">
                  <div className="row justify-content-between align-items-center mb-3">
                    <div className="col-md-6">
                      <div className="mb-4">
                        <ImageWithBasePath
                          src="assets/img/logo.svg"
                          className="img-fluid"
                          alt="SmartHR Logo"
                          height={50}
                        />
                      </div>
                    </div>
                    <div className="col-md-6">
                      <div className="text-end mb-3">
                        <h5 className="text-dark mb-1">Invoice</h5>
                        <p className="mb-1 fw-normal">
                          <i className="ti ti-file-invoice me-1" />
                          INV
                          {getInvoiceNumber(
                            selectedInvoice.companyId || selectedInvoice.id
                          )}
                        </p>
                        <p className="mb-1 fw-normal">
                          <i className="ti ti-calendar me-1" />
                          Issue date : {formatDate(selectedInvoice.CreatedDate)}
                        </p>
                        <p className="fw-normal">
                          <i className="ti ti-calendar me-1" />
                          Due date : {formatDate(selectedInvoice.ExpiringDate)}
                        </p>
                      </div>
                    </div>
                  </div>
                  <div className="row mb-3 d-flex justify-content-between">
                    <div className="col-md-7">
                      <p className="text-dark mb-2 fw-medium fs-16">
                        Invoice From :
                      </p>
                      <div>
                        <p className="mb-1">SmartHR</p>
                        <p className="mb-1">
                          367 Hillcrest Lane, Irvine, California, United States
                        </p>
                        <p className="mb-1">smarthr@example.com</p>
                      </div>
                    </div>
                    <div className="col-md-5">
                      <p className="text-dark mb-2 fw-medium fs-16">
                        Invoice To :
                      </p>
                      <div>
                        <p className="mb-1">{selectedInvoice.CompanyName}</p>
                        <p className="mb-1">{selectedInvoice.CompanyAddress}</p>
                        <p className="mb-1">{selectedInvoice.CompanyEmail}</p>
                      </div>
                    </div>
                  </div>
                  <div className="mb-4">
                    <div className="table-responsive mb-3">
                      <table className="table">
                        <thead className="thead-light">
                          <tr>
                            <th>Plan</th>
                            <th>Billing Cycle</th>
                            <th>Created Date</th>
                            <th>Expiring On</th>
                            <th>Amount</th>
                          </tr>
                        </thead>
                        <tbody>
                          <tr>
                            <td>{selectedInvoice.Plan}</td>
                            <td>{selectedInvoice.BillCycle} Days</td>
                            <td>{formatDate(selectedInvoice.CreatedDate)}</td>
                            <td>{formatDate(selectedInvoice.ExpiringDate)}</td>
                            <td>${selectedInvoice.Amount}</td>
                          </tr>
                        </tbody>
                      </table>
                    </div>
                  </div>
                  <div className="row mb-3 d-flex justify-content-between">
                    <div className="col-md-4">
                      <div className="d-flex justify-content-between align-items-center pe-3">
                        <p className="text-dark fw-medium mb-0">Sub Total</p>
                        <p className="mb-2">${selectedInvoice.Amount}</p>
                      </div>
                      <div className="d-flex justify-content-between align-items-center pe-3">
                        <p className="text-dark fw-medium mb-0">Tax </p>
                        <p className="mb-2">$0.00</p>
                      </div>
                      <div className="d-flex justify-content-between align-items-center pe-3">
                        <p className="text-dark fw-medium mb-0">Total</p>
                        <p className="text-dark fw-medium mb-2">
                          ${selectedInvoice.Amount}
                        </p>
                      </div>
                    </div>
                  </div>
                  <div className="card border mb-0">
                    <div className="card-body">
                      <p className="text-dark fw-medium mb-2">
                        Terms &amp; Conditions:
                      </p>
                      <p className="fs-12 fw-normal d-flex align-items-baseline mb-2">
                        <i className="ti ti-point-filled text-primary me-1" />
                        All payments must be made according to the agreed
                        schedule. Late payments may incur additional fees.
                      </p>
                      <p className="fs-12 fw-normal d-flex align-items-baseline">
                        <i className="ti ti-point-filled text-primary me-1" />
                        We are not liable for any indirect, incidental, or
                        consequential damages, including loss of profits,
                        revenue, or data.
                      </p>
                    </div>
                  </div>
                  <div className="mt-3 text-end">
                    <button
                      className="btn btn-primary"
                      onClick={handleDownloadPDF}
                      id="download-pdf-button"
                      type="button"
                      aria-label="Download PDF"
                    >
                      Download PDF
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </>
  );
};

export default Subscription;
