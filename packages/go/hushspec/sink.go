package hushspec

import (
	"encoding/json"
	"fmt"
	"os"
)

// ReceiptSink persists or forwards decision receipts.
type ReceiptSink interface {
	Send(receipt *DecisionReceipt) error
}

// FileReceiptSink appends receipts as JSON Lines to a file.
type FileReceiptSink struct {
	path string
}

func NewFileReceiptSink(path string) *FileReceiptSink {
	return &FileReceiptSink{path: path}
}

func (s *FileReceiptSink) Send(receipt *DecisionReceipt) error {
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("sink: open file: %w", err)
	}
	defer f.Close()

	data, err := json.Marshal(receipt)
	if err != nil {
		return fmt.Errorf("sink: marshal receipt: %w", err)
	}

	_, err = fmt.Fprintf(f, "%s\n", data)
	if err != nil {
		return fmt.Errorf("sink: write receipt: %w", err)
	}

	return nil
}

// StderrReceiptSink writes pretty-printed receipts to stderr.
type StderrReceiptSink struct{}

func (s *StderrReceiptSink) Send(receipt *DecisionReceipt) error {
	data, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return fmt.Errorf("sink: marshal receipt: %w", err)
	}

	fmt.Fprintf(os.Stderr, "[hushspec] %s\n", data)
	return nil
}

// FilteredSink only forwards receipts matching the configured decisions.
type FilteredSink struct {
	inner     ReceiptSink
	decisions []Decision
}

func NewFilteredSink(sink ReceiptSink, decisions []Decision) *FilteredSink {
	return &FilteredSink{
		inner:     sink,
		decisions: decisions,
	}
}

func NewDenyOnlySink(sink ReceiptSink) *FilteredSink {
	return NewFilteredSink(sink, []Decision{DecisionDeny})
}

func (s *FilteredSink) Send(receipt *DecisionReceipt) error {
	for _, d := range s.decisions {
		if receipt.Decision == d {
			return s.inner.Send(receipt)
		}
	}
	return nil
}

// MultiSink fans out to all sinks. Returns the first error but always
// attempts every sink.
type MultiSink struct {
	sinks []ReceiptSink
}

func NewMultiSink(sinks []ReceiptSink) *MultiSink {
	return &MultiSink{sinks: sinks}
}

func (s *MultiSink) Send(receipt *DecisionReceipt) error {
	var firstErr error
	for _, sink := range s.sinks {
		if err := sink.Send(receipt); err != nil {
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// CallbackSink invokes a function for each receipt.
type CallbackSink struct {
	callback func(*DecisionReceipt) error
}

func NewCallbackSink(callback func(*DecisionReceipt) error) *CallbackSink {
	return &CallbackSink{callback: callback}
}

func (s *CallbackSink) Send(receipt *DecisionReceipt) error {
	return s.callback(receipt)
}

// NullSink discards all receipts.
type NullSink struct{}

func (s *NullSink) Send(receipt *DecisionReceipt) error {
	return nil
}
